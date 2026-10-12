/*
 * to_ebpf.c - translate classic BPF to eBPF instructions.
 *
 * Four things have to be done by hand here (clang would normally do them):
 *
 *   1. Instruction encoding - build code/dst_reg/src_reg/off/imm ourselves.
 *   2. Register allocation  - see the layout below.
 *   3. Jump backpatching    - one cBPF instruction expands to several eBPF
 *                             instructions, so label positions are only known
 *                             after the whole program is emitted (two passes).
 *   4. Packet pointer maths - the verifier only accepts loads it can prove
 *                             safe, which constrains both the bounds checks
 *                             and which register the load is done through.
 *
 * Two rules that are easy to get wrong and cost a lot of debugging:
 *
 *   - Bounds checks must be written as `ptr > pkt_end`. The verifier's
 *     find_good_pkt_pointers() only propagates "the packet is at least this
 *     long" for that direction; the inverted `jle` does not.
 *
 *   - After a check, do NOT recompute the packet pointer from `data`.
 *     Adding a runtime scalar to a packet pointer resets the verifier's
 *     tracked range to 0, so the proof is lost. Reuse the checked register
 *     and only adjust its constant offset.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>

#include "cbpfc.h"
#include "internal.h"

/* cBPF-only classes: in eBPF 0x06 is BPF_JMP32 and 0x07 is BPF_ALU64. */
#define CBPF_RET  0x06
#define CBPF_MISC 0x07
#define CBPF_A    0x10

#define R_A      BPF_REG_6      /* cBPF accumulator */
#define R_X      BPF_REG_7      /* cBPF index */
#define R_T0     BPF_REG_0      /* scratch */
#define R_DATA   BPF_REG_4      /* packet start, supplied by the host */
#define R_END    BPF_REG_5      /* packet end, supplied by the host */

/* cBPF's scratch memory M[0..15]. The host function's frame is ours to use. */
#define FRAG_M(k)       ((int)(-8 - 8 * (k)))

/* The verifier only accepts packet offsets that fit in 16 bits. */
#define MAX_PKT_OFF 0xFFFF

struct fixup {
	size_t at;      /* index of the instruction to patch */
	size_t label;   /* target: a cBPF pc, or n for the trailing block */
};

struct tl {
	struct cbpfc_ebpf_insn *insn;
	size_t                  n, cap;

	/* label[pc] = index of the first eBPF instruction emitted for cBPF pc.
	 * label[n] is the trailing block (early-out / fragment epilogue). */
	size_t                 *label;
	size_t                  n_labels;      /* label[] has this many entries */
	size_t                  end_label;     /* where every failure path lands */
	size_t                  result_label;  /* where the value-carrying exit lands */
	int                     end_used;

	struct fixup           *fix;
	size_t                  nfix, fixcap;

	int                     err;
};

/* Emission primitives */

static void e_ins(struct tl *t, uint8_t code, int dst, int src, int16_t off, int32_t imm)
{
	if (t->err)
		return;
	if (t->n == t->cap) {
		size_t nc = t->cap ? t->cap * 2 : 256;
		struct cbpfc_ebpf_insn *p = realloc(t->insn, nc * sizeof(*p));

		if (!p) {
			t->err = -1;
			return;
		}
		t->insn = p;
		t->cap = nc;
	}
	t->insn[t->n].code    = code;
	t->insn[t->n].dst_reg = (uint8_t)dst;
	t->insn[t->n].src_reg = (uint8_t)src;
	t->insn[t->n].off     = off;
	t->insn[t->n].imm     = imm;
	t->n++;
}

/* Emit a jump whose offset is only known once every label is placed. */
static void e_fix(struct tl *t, uint8_t code, int dst, int src, int32_t imm, size_t label)
{
	if (t->err)
		return;
	if (t->nfix == t->fixcap) {
		size_t nc = t->fixcap ? t->fixcap * 2 : 64;
		struct fixup *p = realloc(t->fix, nc * sizeof(*p));

		if (!p) {
			t->err = -1;
			return;
		}
		t->fix = p;
		t->fixcap = nc;
	}
	t->fix[t->nfix].at    = t->n;
	t->fix[t->nfix].label = label;
	t->nfix++;
	if (label == t->end_label)
		t->end_used = 1;

	e_ins(t, code, dst, src, 0, imm);
}

static void e_to_label(struct tl *t, size_t label)
{
	e_fix(t, BPF_JMP | BPF_JA, 0, 0, 0, label);
}

/* Bail out of the whole filter: "no match".
 *
 * The target is the trailing block, which for a standalone program is
 * `r0 = 0; exit` and for a fragment is `r0 = 0` followed by the epilogue.
 * A failing path must never fall through with a stale r0, so it goes to that
 * block rather than straight to the epilogue. */
static void e_bail(struct tl *t)
{
	e_to_label(t, t->end_label);
}

static void e_bail_if(struct tl *t, uint8_t code, int dst, int src, int32_t imm)
{
	e_fix(t, code, dst, src, imm, t->end_label);
}

static void e_mov64(struct tl *t, int d, int s)
{
	e_ins(t, BPF_ALU64 | BPF_MOV | BPF_X, d, s, 0, 0);
}

static void e_mov32(struct tl *t, int d, int s)
{
	e_ins(t, BPF_ALU | BPF_MOV | BPF_X, d, s, 0, 0);
}

static void e_add64i(struct tl *t, int d, int32_t i)
{
	e_ins(t, BPF_ALU64 | BPF_ADD | BPF_K, d, 0, 0, i);
}

static void e_add64x(struct tl *t, int d, int s)
{
	e_ins(t, BPF_ALU64 | BPF_ADD | BPF_X, d, s, 0, 0);
}

static void e_alu(struct tl *t, uint8_t op, int by_x, int32_t k)
{
	/* 32-bit ALU throughout: that matches cBPF's 32-bit wraparound and the
	 * zero-extension of the upper 32 bits is free. */
	e_ins(t, BPF_ALU | op | (by_x ? BPF_X : BPF_K), R_A, by_x ? R_X : 0, 0, k);
}

static uint8_t size_cls(int size)
{
	return (uint8_t)(size == 4 ? BPF_W : size == 2 ? BPF_H : BPF_B);
}

static int width_bytes(uint16_t code)
{
	switch (code & 0x18) {
	case BPF_W: return 4;
	case BPF_H: return 2;
	default:    return 1;
	}
}

/* Loads are big endian; on a little-endian host that is a byte swap. */
static void e_bswap(struct tl *t, int reg, int size)
{
	if (size == 2)
		e_ins(t, BPF_ALU | BPF_END | BPF_TO_BE, reg, 0, 0, 16);
	if (size == 4)
		e_ins(t, BPF_ALU | BPF_END | BPF_TO_BE, reg, 0, 0, 32);
}

/* if (data + n > data_end) -> bail */
static void e_bound(struct tl *t, int32_t n)
{
	e_mov64(t, R_T0, R_DATA);
	e_add64i(t, R_T0, n);
	e_bail_if(t, BPF_JMP | BPF_JGT | BPF_X, R_T0, R_END, 0);
}

/* Absolute packet load at a constant offset. */
static void e_load_abs(struct tl *t, uint32_t k, int size)
{
	e_bound(t, (int32_t)(k + (uint32_t)size));

	/* A constant offset belongs in the instruction's own `off` field, with
	 * the base pointer left alone - that keeps the verifier's proof intact.
	 * This is also what clang generates. */
	if (k <= 32767) {
		e_ins(t, BPF_LDX | BPF_MEM | size_cls(size), R_T0, R_DATA, (int16_t)k, 0);
	} else {
		e_mov64(t, R_T0, R_DATA);
		e_add64i(t, R_T0, (int32_t)k);
		e_ins(t, BPF_LDX | BPF_MEM | size_cls(size), R_T0, R_T0, 0, 0);
	}
	e_bswap(t, R_T0, size);
	e_mov32(t, R_A, R_T0);
}

/* Indirect packet load at x + k, where x is a runtime value. */
static void e_load_ind(struct tl *t, uint32_t k, int size)
{
	uint32_t end = k + (uint32_t)size;

	if (end > MAX_PKT_OFF) {
		/* The offset cannot fit in the verifier's 16-bit limit, so this
		 * load can never match. */
		e_bail(t);
		return;
	}

	/* x is unbounded as far as the verifier knows; bound it first so that
	 * "packet pointer + x" is accepted. */
	e_ins(t, BPF_ALU64 | BPF_MOV | BPF_K, R_T0, 0, 0, (int32_t)(MAX_PKT_OFF - end));
	e_bail_if(t, BPF_JMP | BPF_JGT | BPF_X, R_X, R_T0, 0);

	/* if (data + x + end > data_end) -> bail */
	e_mov64(t, R_T0, R_DATA);
	e_add64x(t, R_T0, R_X);
	e_add64i(t, R_T0, (int32_t)end);
	e_bail_if(t, BPF_JMP | BPF_JGT | BPF_X, R_T0, R_END, 0);

	/* Do NOT rebuild the pointer from `data` here: adding a runtime scalar
	 * to a packet pointer resets the verifier's range to 0 and the load is
	 * rejected. Adjust the constant offset on the register we just proved
	 * safe instead (end - k == size). */
	e_add64i(t, R_T0, -(int32_t)size);
	e_ins(t, BPF_LDX | BPF_MEM | size_cls(size), R_T0, R_T0, 0, 0);
	e_bswap(t, R_T0, size);
	e_mov32(t, R_A, R_T0);
}

/* Conditional jumps */

static uint8_t invert_jmp(uint8_t op)
{
	switch (op) {
	case BPF_JEQ: return BPF_JNE;
	case BPF_JNE: return BPF_JEQ;
	case BPF_JGT: return BPF_JLE;
	case BPF_JLE: return BPF_JGT;
	case BPF_JGE: return BPF_JLT;
	default:      return BPF_JGE;   /* BPF_JLT */
	}
}

/* One cBPF conditional jump -> one to three eBPF instructions.
 * Targets at or past n mean "fell off the end", which is a non-match. */
static void emit_cond(struct tl *t, uint8_t jop, int by_x, uint32_t k,
		      size_t pc, size_t tt, size_t tf, size_t n)
{
	size_t  lt  = (tt < n) ? tt : t->end_label;
	size_t  lf  = (tf < n) ? tf : t->end_label;
	uint8_t cls;
	int     src;
	int32_t imm;

	if (by_x) {
		cls = BPF_X;
		src = R_X;
		imm = 0;
	} else if ((int32_t)k < 0) {
		/* A 64-bit compare sign-extends a BPF_K operand, while cBPF's A is
		 * zero-extended: `jeq #0xC0A80101` would compare 0xFFFFFFFFC0A80101
		 * against 0x00000000C0A80101 and never match. Load the constant with
		 * a 32-bit move - which zero-extends - and compare registers. */
		e_ins(t, BPF_ALU | BPF_MOV | BPF_K, R_T0, 0, 0, (int32_t)k);
		cls = BPF_X;
		src = R_T0;
		imm = 0;
	} else {
		cls = BPF_K;
		src = 0;
		imm = (int32_t)k;
	}

	/* With a register operand, imm is a reserved field and must be zero,
	 * otherwise the verifier reports "BPF_JMP uses reserved fields". */
	if (src)
		imm = 0;

	if (tt == pc + 1 && jop != BPF_JSET) {
		/* The true branch falls through: invert and emit one jump. */
		e_fix(t, BPF_JMP | invert_jmp(jop) | cls, R_A, src, imm, lf);
	} else if (tf == pc + 1) {
		e_fix(t, BPF_JMP | jop | cls, R_A, src, imm, lt);
	} else if (tt == pc + 1) {
		/* jset has no single-instruction inverse. */
		e_ins(t, BPF_JMP | BPF_JSET | cls, R_A, src, 1, imm);
		e_to_label(t, lf);
	} else {
		e_fix(t, BPF_JMP | jop | cls, R_A, src, imm, lt);
		e_to_label(t, lf);
	}
}

/* Return */

/* Every exit jumps to the epilogue, carrying the result in r0, and then
 * falls through into the host function body. */
static void emit_exit(struct tl *t)
{
	e_to_label(t, t->result_label);
}

/* Leave the cBPF return value in r0. Mapping it onto whatever the host
 * needs (a TC action code, a boolean, ...) is the host's job. */
static void emit_ret(struct tl *t, int have_a, uint32_t k)
{
	if (have_a)
		e_mov32(t, R_T0, R_A);
	else
		e_ins(t, BPF_ALU | BPF_MOV | BPF_K, R_T0, 0, 0, (int32_t)k);
	emit_exit(t);
}

/* Prologue / epilogue */

/* Fragment prologue. r4/r5 arrive from the host; all we do is zero cBPF's
 * accumulator, index and scratch memory. No helper is called, so r4/r5 stay
 * where the host put them for the whole run. */
static void emit_frag_prologue(struct tl *t)
{
	int k;

	e_ins(t, BPF_ALU | BPF_MOV | BPF_K, R_A, 0, 0, 0);
	e_ins(t, BPF_ALU | BPF_MOV | BPF_K, R_X, 0, 0, 0);
	for (k = 0; k < 16; k++)
		e_ins(t, BPF_STX | BPF_MEM | BPF_W, BPF_REG_10, R_A,
		      (int16_t)FRAG_M(k), 0);
}

/* Fragment epilogue: hand the result back to the host function body.
 * r4 = result, r5/r1/r2/r3 = 0, so the body's
 *   `(data != data_end) && (a == b) && (b == c)`
 * evaluates to "result != 0". */
static void emit_frag_epilogue(struct tl *t)
{
	e_mov64(t, BPF_REG_4, R_T0);
	e_ins(t, BPF_ALU | BPF_MOV | BPF_K, BPF_REG_5, 0, 0, 0);
	e_ins(t, BPF_ALU | BPF_MOV | BPF_K, BPF_REG_1, 0, 0, 0);
	e_ins(t, BPF_ALU | BPF_MOV | BPF_K, BPF_REG_2, 0, 0, 0);
	e_ins(t, BPF_ALU | BPF_MOV | BPF_K, BPF_REG_3, 0, 0, 0);
}

static void emit_prologue(struct tl *t)
{
	emit_frag_prologue(t);
}

/* Per-instruction translation */

static int emit_one(struct tl *t, const struct cbpfc_insn *in, size_t pc, size_t n)
{
	int size;

	switch (in->code) {

	/* loads: immediate / packet length / scratch */
	case BPF_LD  | BPF_W | BPF_IMM:
		e_ins(t, BPF_ALU | BPF_MOV | BPF_K, R_A, 0, 0, (int32_t)in->k);
		break;
	case BPF_LDX | BPF_W | BPF_IMM:
		e_ins(t, BPF_ALU | BPF_MOV | BPF_K, R_X, 0, 0, (int32_t)in->k);
		break;

	case BPF_LD  | BPF_W | BPF_LEN:
		e_mov64(t, R_A, R_END);
		e_ins(t, BPF_ALU64 | BPF_SUB | BPF_X, R_A, R_DATA, 0, 0);
		break;
	case BPF_LDX | BPF_W | BPF_LEN:
		e_mov64(t, R_X, R_END);
		e_ins(t, BPF_ALU64 | BPF_SUB | BPF_X, R_X, R_DATA, 0, 0);
		break;

	case BPF_LD  | BPF_W | BPF_MEM:
	case BPF_LDX | BPF_W | BPF_MEM:
		if (in->k >= 16)
			return -1;
		e_ins(t, BPF_LDX | BPF_MEM | BPF_W,
		      in->code == (BPF_LD | BPF_W | BPF_MEM) ? R_A : R_X,
		      BPF_REG_10, (int16_t)FRAG_M(in->k), 0);
		break;

	case BPF_ST:
		if (in->k >= 16)
			return -1;
		e_ins(t, BPF_STX | BPF_MEM | BPF_W, BPF_REG_10, R_A,
		      (int16_t)FRAG_M(in->k), 0);
		break;
	case BPF_STX:
		if (in->k >= 16)
			return -1;
		e_ins(t, BPF_STX | BPF_MEM | BPF_W, BPF_REG_10, R_X,
		      (int16_t)FRAG_M(in->k), 0);
		break;

	/* loads from the packet */
	case BPF_LD | BPF_W | BPF_ABS:
	case BPF_LD | BPF_H | BPF_ABS:
	case BPF_LD | BPF_B | BPF_ABS:
		size = width_bytes(in->code);
		if ((uint64_t)in->k + (uint64_t)size > MAX_PKT_OFF)
			e_bail(t);
		else
			e_load_abs(t, in->k, size);
		break;

	case BPF_LD | BPF_W | BPF_IND:
	case BPF_LD | BPF_H | BPF_IND:
	case BPF_LD | BPF_B | BPF_IND:
		e_load_ind(t, in->k, width_bytes(in->code));
		break;

	case BPF_LDX | BPF_B | BPF_MSH:                 /* ldxb 4*([k]&0xf) */
		if ((uint64_t)in->k + 1 > MAX_PKT_OFF) {
			e_bail(t);
			break;
		}
		e_bound(t, (int32_t)(in->k + 1));
		e_ins(t, BPF_LDX | BPF_MEM | BPF_B, R_T0, R_DATA, (int16_t)in->k, 0);
		e_ins(t, BPF_ALU | BPF_AND | BPF_K, R_T0, 0, 0, 0x0f);
		e_ins(t, BPF_ALU | BPF_LSH | BPF_K, R_T0, 0, 0, 2);
		e_mov32(t, R_X, R_T0);
		break;

	/* ALU */
	case BPF_ALU | BPF_ADD | BPF_K: e_alu(t, BPF_ADD, 0, (int32_t)in->k); break;
	case BPF_ALU | BPF_ADD | BPF_X: e_alu(t, BPF_ADD, 1, 0); break;
	case BPF_ALU | BPF_SUB | BPF_K: e_alu(t, BPF_SUB, 0, (int32_t)in->k); break;
	case BPF_ALU | BPF_SUB | BPF_X: e_alu(t, BPF_SUB, 1, 0); break;
	case BPF_ALU | BPF_MUL | BPF_K: e_alu(t, BPF_MUL, 0, (int32_t)in->k); break;
	case BPF_ALU | BPF_MUL | BPF_X: e_alu(t, BPF_MUL, 1, 0); break;
	case BPF_ALU | BPF_AND | BPF_K: e_alu(t, BPF_AND, 0, (int32_t)in->k); break;
	case BPF_ALU | BPF_AND | BPF_X: e_alu(t, BPF_AND, 1, 0); break;
	case BPF_ALU | BPF_OR  | BPF_K: e_alu(t, BPF_OR,  0, (int32_t)in->k); break;
	case BPF_ALU | BPF_OR  | BPF_X: e_alu(t, BPF_OR,  1, 0); break;
	case BPF_ALU | BPF_XOR | BPF_K: e_alu(t, BPF_XOR, 0, (int32_t)in->k); break;
	case BPF_ALU | BPF_XOR | BPF_X: e_alu(t, BPF_XOR, 1, 0); break;
	case BPF_ALU | BPF_NEG:
		e_ins(t, BPF_ALU | BPF_NEG, R_A, 0, 0, 0);
		break;

	/* Division by zero makes the whole filter fail (cBPF semantics). */
	case BPF_ALU | BPF_DIV | BPF_K:
		if (in->k == 0)
			e_bail(t);
		else
			e_alu(t, BPF_DIV, 0, (int32_t)in->k);
		break;
	case BPF_ALU | BPF_DIV | BPF_X:
		e_bail_if(t, BPF_JMP | BPF_JEQ | BPF_K, R_X, 0, 0);
		e_alu(t, BPF_DIV, 1, 0);
		break;
	case BPF_ALU | BPF_MOD | BPF_X:
		e_bail_if(t, BPF_JMP | BPF_JEQ | BPF_K, R_X, 0, 0);
		e_alu(t, BPF_MOD, 1, 0);
		break;
	/* `mod #0` leaves A unchanged (libpcap's behaviour), so it is a no-op. */
	case BPF_ALU | BPF_MOD | BPF_K:
		if (in->k != 0)
			e_alu(t, BPF_MOD, 0, (int32_t)in->k);
		break;

	/* Shifts. The immediate form masks the amount to 5 bits, the register
	 * form yields 0 for amounts >= 32; both match libpcap's bpf_filter. */
	case BPF_ALU | BPF_LSH | BPF_K:
		e_alu(t, BPF_LSH, 0, (int32_t)(in->k & 31));
		break;
	case BPF_ALU | BPF_RSH | BPF_K:
		e_alu(t, BPF_RSH, 0, (int32_t)(in->k & 31));
		break;
	case BPF_ALU | BPF_LSH | BPF_X:
	case BPF_ALU | BPF_RSH | BPF_X:
		e_alu(t, (in->code & 0xf0) == BPF_LSH ? BPF_LSH : BPF_RSH, 1, 0);
		/* eBPF masks a register shift by 31, so shift first and then
		 * overwrite with zero when the amount was out of range. */
		e_ins(t, BPF_JMP | BPF_JLE | BPF_K, R_X, 0, 1, 31);
		e_ins(t, BPF_ALU | BPF_MOV | BPF_K, R_A, 0, 0, 0);
		break;

	/* jumps: target = pc + 1 + jt/jf */
	case BPF_JMP | BPF_JA:
		if (pc + 1 + in->k < n)
			e_to_label(t, pc + 1 + in->k);
		else if (pc + 1 + in->k == pc + 1)
			break;                          /* jump to the next insn */
		else
			e_bail(t);                      /* past the end */
		break;

	case BPF_JMP | BPF_JEQ  | BPF_K: case BPF_JMP | BPF_JEQ  | BPF_X:
		emit_cond(t, BPF_JEQ,  in->code & BPF_X, in->k, pc,
			  pc + 1 + in->jt, pc + 1 + in->jf, n);
		break;
	case BPF_JMP | BPF_JGT  | BPF_K: case BPF_JMP | BPF_JGT  | BPF_X:
		emit_cond(t, BPF_JGT,  in->code & BPF_X, in->k, pc,
			  pc + 1 + in->jt, pc + 1 + in->jf, n);
		break;
	case BPF_JMP | BPF_JGE  | BPF_K: case BPF_JMP | BPF_JGE  | BPF_X:
		emit_cond(t, BPF_JGE,  in->code & BPF_X, in->k, pc,
			  pc + 1 + in->jt, pc + 1 + in->jf, n);
		break;
	case BPF_JMP | BPF_JSET | BPF_K: case BPF_JMP | BPF_JSET | BPF_X:
		emit_cond(t, BPF_JSET, in->code & BPF_X, in->k, pc,
			  pc + 1 + in->jt, pc + 1 + in->jf, n);
		break;

	/* return */
	case CBPF_RET | BPF_K:  emit_ret(t, 0, in->k); break;
	case CBPF_RET | CBPF_A: emit_ret(t, 1, 0);     break;

	/* register moves */
	case CBPF_MISC | 0x00: e_mov32(t, R_X, R_A); break;   /* tax */
	case CBPF_MISC | 0x80: e_mov32(t, R_A, R_X); break;   /* txa */

	default:
		return -1;
	}
	return 0;
}

/* Control flow analysis */

/* Mark every instruction reachable from pc 0.
 *
 * A C compiler would drop dead code silently, but the eBPF verifier rejects
 * any unreachable instruction, so the dead ones have to be skipped here. */
static void mark_reachable(const struct cbpfc_insn *p, size_t n, char *reach)
{
	size_t *stack = malloc(n * sizeof(*stack));
	size_t  sp = 0;

	memset(reach, 0, n);
	if (!stack || n == 0) {
		free(stack);
		return;
	}

	reach[0] = 1;
	stack[sp++] = 0;

	while (sp) {
		size_t   pc = stack[--sp];
		uint16_t c = p[pc].code;
		size_t   nx[2];
		int      k = 0, i;

		if ((c & 0x07) == BPF_JMP) {
			if (c == (BPF_JMP | BPF_JA)) {
				nx[k++] = pc + 1 + p[pc].k;
			} else {
				nx[k++] = pc + 1 + p[pc].jt;
				nx[k++] = pc + 1 + p[pc].jf;
			}
		} else if ((c & 0x07) == CBPF_RET) {
			/* no successors */
		} else {
			nx[k++] = pc + 1;
		}

		for (i = 0; i < k; i++) {
			if (nx[i] < n && !reach[nx[i]]) {
				reach[nx[i]] = 1;
				stack[sp++] = nx[i];
			}
		}
	}
	free(stack);
}

/* Does control fall off the end of the program? If so the trailing block is
 * reachable and has to be emitted; otherwise it would be dead code. */
static int falls_off_end(const struct cbpfc_insn *p, size_t n, const char *reach)
{
	size_t i;

	for (i = 0; i < n; i++) {
		uint16_t c;

		if (!reach[i])
			continue;
		c = p[i].code;
		if ((c & 0x07) == BPF_JMP)
			continue;               /* both targets are explicit */
		if ((c & 0x07) == CBPF_RET)
			continue;               /* ret never falls through */
		if (i + 1 >= n)
			return 1;
	}
	return 0;
}

/**
 * cbpfc_to_ebpf:
 * @p: the cBPF program
 * @n: number of instructions in @p
 * @out: returns the compiled fragment
 *
 * Compiles cBPF to an eBPF *fragment* - not a loadable program. It is meant to
 * go in front of the body of a placeholder function in a host program, which
 * is what cbpfc_inject() does.
 *
 * The fragment's contract (the same as pwru's):
 *
 *	input	r4 = packet start, r5 = packet end
 *	output	r4 = the cBPF return value (0 = no match, non-zero = match),
 *		r1/r2/r3/r5 = 0, then fall through into whatever follows
 *
 * It writes r0, r6, r7 and the stack, leaves r8/r9 alone and calls no helper,
 * so the host has nothing to save across it.
 *
 * The value is the cBPF one, not a TC or XDP verdict. Handing it straight to a
 * TC classifier would not work: the kernel's sch_handle_egress() switches on
 * the return value, recognises neither 0 nor 262144, and passes for both - so
 * both branches would pass and the filter would do nothing. The host is where
 * that mapping belongs, and its placeholder body is where it happens.
 *
 * Returns: 0 on success, -1 if @p is empty or holds an instruction this
 * compiler does not handle - see cbpfc_errmsg()
 */
int cbpfc_to_ebpf(const struct cbpfc_insn *p, size_t n,
		  struct cbpfc_ebpf_prog *out)
{
	struct tl t;
	int       rc = -1;
	size_t    i;

	memset(&t, 0, sizeof(t));
	/* Two synthetic labels follow the last cBPF pc: label[n] is the failure
	 * block (forces "no match") and label[n+1] is the epilogue. */
	t.n_labels = n + 2;
	t.end_label = n;
	t.result_label = n + 1;

	out->insn = NULL;
	out->n    = 0;

	cbpfc_err_clear();

	if (n == 0) {
		cbpfc_err_set("no instructions to compile");
		return -1;
	}

	t.label = malloc(t.n_labels * sizeof(*t.label));
	if (!t.label) {
		cbpfc_err_set("out of memory");
		return -1;
	}
	for (i = 0; i < t.n_labels; i++)
		t.label[i] = (size_t)-1;

	emit_prologue(&t);

	{
		char *reach = malloc(n);
		int   off_end;

		if (!reach) {
			cbpfc_err_set("out of memory");
			goto out;
		}
		mark_reachable(p, n, reach);
		off_end = falls_off_end(p, n, reach);

		for (i = 0; i < n; i++) {
			if (!reach[i])
				continue;
			t.label[i] = t.n;
			if (emit_one(&t, &p[i], i, n) != 0) {
				cbpfc_err_set("instruction %zu (code 0x%02x) is not"
					      " supported", i, p[i].code);
				free(reach);
				goto out;
			}
		}
		free(reach);

		/* Falling off the end also has no result to report. */
		if (off_end)
			t.end_used = 1;

		/* Failure block: a bailed-out path has no meaningful result in r0,
		 * so force "no match" before the epilogue. Emitted only when
		 * something actually jumps there - the verifier rejects
		 * unreachable instructions. */
		if (t.end_used && !t.err) {
			t.label[n] = t.n;
			e_ins(&t, BPF_ALU | BPF_MOV | BPF_K, R_T0, 0, 0, 0);
		}

		/* Epilogue: hands the result to the host function body. */
		t.label[t.result_label] = t.n;
		emit_frag_epilogue(&t);
	}

	if (t.err) {
		cbpfc_err_set("out of memory");
		goto out;
	}

	/* Second pass: every label is known now, so resolve the jumps. */
	for (i = 0; i < t.nfix; i++) {
		size_t at = t.fix[i].at;
		size_t lb = t.fix[i].label;
		long   d;

		if (lb >= t.n_labels || t.label[lb] == (size_t)-1) {
			cbpfc_err_set("a jump points at an instruction that is not"
				      " reachable");
			goto out;
		}
		d = (long)t.label[lb] - (long)at - 1;
		if (d < -32768 || d > 32767) {
			cbpfc_err_set("a jump is too far for a 16-bit offset");
			goto out;
		}
		t.insn[at].off = (int16_t)d;
	}

	out->insn = t.insn;
	out->n    = t.n;
	t.insn    = NULL;
	rc = 0;

out:
	free(t.label);
	free(t.fix);
	free(t.insn);
	return rc;
}

/**
 * cbpfc_ebpf_prog_free:
 * @p: the fragment to release
 *
 * Releases the instructions held by @p and resets it.
 */
void cbpfc_ebpf_prog_free(struct cbpfc_ebpf_prog *p)
{
	free(p->insn);
	p->insn = NULL;
	p->n = 0;
}

/* Disassembler (covers the instructions this compiler emits) */

static const char *alu_name(uint8_t op)
{
	switch (op) {
	case BPF_ADD: return "add";  case BPF_SUB: return "sub";
	case BPF_MUL: return "mul";  case BPF_DIV: return "div";
	case BPF_OR:  return "or";   case BPF_AND: return "and";
	case BPF_LSH: return "lsh";  case BPF_RSH: return "rsh";
	case BPF_NEG: return "neg";  case BPF_MOD: return "mod";
	case BPF_XOR: return "xor";  case BPF_MOV: return "mov";
	case BPF_END: return "end";
	default:      return "?";
	}
}

static const char *jmp_op(uint8_t op)
{
	switch (op) {
	case BPF_JEQ:  return "==";  case BPF_JNE: return "!=";
	case BPF_JGT:  return ">";   case BPF_JGE: return ">=";
	case BPF_JLT:  return "<";   case BPF_JLE: return "<=";
	case BPF_JSET: return "&";
	default:       return "?";
	}
}

/**
 * cbpfc_disasm:
 * @buf: buffer for the result, filled with a NUL-terminated string
 * @bufsz: size of @buf
 * @in: the instruction to format
 *
 * Formats @in the way llvm-objdump does.
 */
void cbpfc_disasm(char *buf, size_t bufsz, const struct cbpfc_ebpf_insn *in)
{
	const char *sfx = (in->code & 0x18) == BPF_W ? "w" :
			  (in->code & 0x18) == BPF_H ? "h" : "b";

	switch (in->code & 0x07) {
	case BPF_ALU64:
	case BPF_ALU:
		if ((in->code & 0xf0) == BPF_END) {
			snprintf(buf, bufsz, "r%d = %s%d r%d", in->dst_reg,
				 (in->code & 0x08) ? "be" : "le", in->imm, in->dst_reg);
		} else if (in->code & BPF_X) {
			snprintf(buf, bufsz, "%s%d r%d, r%d",
				 alu_name(in->code & 0xf0),
				 (in->code & 0x07) == BPF_ALU64 ? 64 : 32,
				 in->dst_reg, in->src_reg);
		} else {
			snprintf(buf, bufsz, "%s%d r%d, %d",
				 alu_name(in->code & 0xf0),
				 (in->code & 0x07) == BPF_ALU64 ? 64 : 32,
				 in->dst_reg, in->imm);
		}
		break;

	case BPF_LDX:
	case BPF_STX:
		if ((in->code & 0xe0) == BPF_MEM) {
			if ((in->code & 0x07) == BPF_STX)
				snprintf(buf, bufsz, "*(%s *)(r%d %+d) = r%d", sfx,
					 in->dst_reg, in->off, in->src_reg);
			else
				snprintf(buf, bufsz, "r%d = *(%s *)(r%d %+d)", in->dst_reg,
					 sfx, in->src_reg, in->off);
		} else {
			snprintf(buf, bufsz, "ldx/%02x r%d, r%d %+d",
				 in->code, in->dst_reg, in->src_reg, in->off);
		}
		break;

	case BPF_JMP:
	case BPF_JMP32:
		if ((in->code & 0xf0) == BPF_EXIT) {
			snprintf(buf, bufsz, "exit");
			break;
		}
		if (in->code == (BPF_JMP | BPF_JA)) {
			snprintf(buf, bufsz, "goto %+d", in->off);
			break;
		}
		if (in->code & BPF_X)
			snprintf(buf, bufsz, "if r%d %s r%d goto %+d", in->dst_reg,
				 jmp_op(in->code & 0xf0), in->src_reg, in->off);
		else
			snprintf(buf, bufsz, "if r%d %s %d goto %+d", in->dst_reg,
				 jmp_op(in->code & 0xf0), in->imm, in->off);
		break;

	default:
		snprintf(buf, bufsz, ".byte %02x", in->code);
		break;
	}
}
