/*
 * to_c.c - translate classic BPF to C source.
 *
 * This is the easy backend: C has real labels, so `goto block_<pc>` needs no
 * offset arithmetic at all. The hard part (backpatching) only shows up when
 * emitting eBPF directly - see to_ebpf.c.
 *
 * The generated function is:
 *
 *     uint32_t filter(const uint8_t *data, const uint8_t *data_end)
 *
 * returning the cBPF ret value: 0 means "no match", non-zero "match".
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbpfc.h"

/* Opcode encoding, grouped the way <linux/bpf_common.h> groups it. */
#define BPF_LD    0x00
#define BPF_LDX   0x01
#define BPF_ST    0x02
#define BPF_STX   0x03
#define BPF_ALU   0x04
#define BPF_JMP   0x05
#define BPF_RET   0x06
#define BPF_MISC  0x07

#define BPF_W     0x00
#define BPF_H     0x08
#define BPF_B     0x10

#define BPF_IMM   0x00
#define BPF_ABS   0x20
#define BPF_IND   0x40
#define BPF_MEM   0x60
#define BPF_LEN   0x80
#define BPF_MSH   0xa0

#define BPF_K     0x00
#define BPF_X     0x08
#define BPF_A     0x10

#define BPF_ADD   0x00
#define BPF_SUB   0x10
#define BPF_MUL   0x20
#define BPF_DIV   0x30
#define BPF_OR    0x40
#define BPF_AND   0x50
#define BPF_LSH   0x60
#define BPF_RSH   0x70
#define BPF_NEG   0x80
#define BPF_MOD   0x90
#define BPF_XOR   0xa0

#define BPF_JA    0x00
#define BPF_JEQ   0x10
#define BPF_JGT   0x20
#define BPF_JGE   0x30
#define BPF_JSET  0x40

#define BPF_TAX   0x00
#define BPF_TXA   0x80

/* The verifier caps packet offsets at 16 bits; beyond that a load can never
 * match, so the block is turned into an unconditional "return 0". */
#define MAX_PKT_OFF 0xFFFF

static uint32_t width_of(uint16_t code)
{
	switch (code & 0x18) {
	case BPF_W: return 4;
	case BPF_H: return 2;
	default:    return 1;
	}
}

/* Emit a jump target. A target at or past n means control leaves the program,
 * which per cBPF semantics is a non-match. */
static void emit_target(FILE *o, size_t target, size_t n, const char *ind)
{
	if (target < n)
		fprintf(o, "%sgoto block_%zu;\n", ind, target);
	else
		fprintf(o, "%sreturn 0;                 /* ran off the end */\n", ind);
}

/* A packet read: prove the packet is long enough first, then read.
 *
 * An absolute offset is a compile-time constant, so the check is a constant
 * too. An indirect offset (x + k) needs x to be bounded as well. */
static void emit_load(FILE *o, uint16_t code, uint32_t k, int indirect)
{
	uint32_t size = width_of(code);

	if (indirect) {
		uint64_t end = (uint64_t)k + size;

		if (end > MAX_PKT_OFF)
			fprintf(o, "    return 0;             /* offset %u+%u exceeds 65535 */\n",
				k, size);
		else {
			fprintf(o, "    if (x > %u) return 0;                  /* bound x for the verifier */\n",
				(unsigned)(MAX_PKT_OFF - end));
			fprintf(o, "    if (data + x + %u > data_end) return 0;  /* out of bounds = no match */\n",
				(unsigned)end);
		}
	} else {
		if ((uint64_t)k + size > MAX_PKT_OFF)
			fprintf(o, "    return 0;             /* offset %u+%u exceeds 65535 */\n",
				k, size);
		else
			fprintf(o, "    if (data + %u > data_end) return 0;      /* out of bounds = no match */\n",
				k + size);
	}

	if (indirect) {
		switch (code & 0x18) {
		case BPF_W: fprintf(o, "    a = cbpf_be32(data + x + %u);\n", k); break;
		case BPF_H: fprintf(o, "    a = cbpf_be16(data + x + %u);\n", k); break;
		default:    fprintf(o, "    a = (data + x + %u)[0];\n", k);        break;
		}
	} else {
		switch (code & 0x18) {
		case BPF_W: fprintf(o, "    a = cbpf_be32(data + %u);\n", k); break;
		case BPF_H: fprintf(o, "    a = cbpf_be16(data + %u);\n", k); break;
		default:    fprintf(o, "    a = data[%u];\n", k);             break;
		}
	}
}

static void emit_jump_cond(FILE *o, uint16_t code, uint32_t k)
{
	int  by_x = (code & 0x08) != 0;
	char rhs[32];

	if (by_x)
		snprintf(rhs, sizeof(rhs), "x");
	else
		snprintf(rhs, sizeof(rhs), "%uu", k);

	switch (code & 0xf0) {
	case BPF_JEQ:  fprintf(o, "a == %s", rhs);   break;
	case BPF_JGT:  fprintf(o, "a > %s", rhs);    break;   /* unsigned */
	case BPF_JGE:  fprintf(o, "a >= %s", rhs);   break;
	default:       fprintf(o, "(a & %s)", rhs);  break;   /* BPF_JSET */
	}
}

/* Only label the pcs that are actually jumped to. cBPF jumps are
 * forward-only, so pc 0 is never a target. */
static void mark_targets(const struct cbpfc_insn *p, size_t n, char *need)
{
	size_t pc;

	memset(need, 0, n);

	for (pc = 0; pc < n; pc++) {
		if ((p[pc].code & 0x07) != BPF_JMP)
			continue;

		if (p[pc].code == (BPF_JMP | BPF_JA)) {
			size_t t = pc + 1 + p[pc].k;

			if (t < n)
				need[t] = 1;
		} else {
			size_t t = pc + 1 + p[pc].jt;
			size_t f = pc + 1 + p[pc].jf;

			if (t < n)
				need[t] = 1;
			if (f < n)
				need[f] = 1;
		}
	}
}

/* Are the big-endian helpers actually used? Emitting only the ones needed
 * keeps the output warning-free under -Wall. */
static void scan_widths(const struct cbpfc_insn *p, size_t n, int *need16, int *need32)
{
	size_t i;

	*need16 = *need32 = 0;
	for (i = 0; i < n; i++) {
		uint16_t c = p[i].code;

		if (c == (BPF_LD | BPF_H | BPF_ABS) || c == (BPF_LD | BPF_H | BPF_IND))
			*need16 = 1;
		if (c == (BPF_LD | BPF_W | BPF_ABS) || c == (BPF_LD | BPF_W | BPF_IND))
			*need32 = 1;
	}
}

static void emit_prologue(FILE *o, int for_ebpf, int need16, int need32)
{
	fputs("/* Generated by libcbpfc - do not edit. */\n", o);
	fputs("#include <stdint.h>\n", o);
	if (for_ebpf)
		fputs("#include <linux/bpf.h>\n"
		      "#include <linux/pkt_cls.h>\n"      /* TC_ACT_OK / TC_ACT_SHOT */
		      "#include <bpf/bpf_helpers.h>\n", o);

	if (need16 || need32)
		fputs("\n/* Big-endian reads, assembled byte by byte so no unaligned\n"
		      " * access is performed and clang -target bpf accepts them. */\n", o);
	if (need16)
		fputs("static inline uint16_t cbpf_be16(const uint8_t *p)\n"
		      "{\n"
		      "    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);\n"
		      "}\n", o);
	if (need32)
		fputs("static inline uint32_t cbpf_be32(const uint8_t *p)\n"
		      "{\n"
		      "    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |\n"
		      "           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];\n"
		      "}\n", o);

	fputs("\n/* data..data_end is the packet; the return value is the number of\n"
	      " * bytes to keep, 0 meaning \"no match\". */\n", o);

	/* For eBPF the function must be inlined: otherwise it becomes a real BPF
	 * subprogram and the verifier refuses to pass a packet pointer into it
	 * ("Caller passes invalid args into func"). */
	fputs(for_ebpf ? "static inline __attribute__((always_inline))\n"
			  "uint32_t filter(const uint8_t *data, const uint8_t *data_end)\n"
			: "uint32_t filter(const uint8_t *data, const uint8_t *data_end)\n", o);
	fputs("{\n"
	      "    uint32_t a = 0, x = 0, m[16] = {0};\n"
	      "    (void)data; (void)data_end; (void)a; (void)x; (void)m;\n"
	      "\n", o);
}

static int translate(FILE *out, const struct cbpfc_insn *p, size_t n, int for_ebpf)
{
	char *need;
	int   rc = 0, need16, need32;
	size_t pc;

	if (n == 0)
		return -1;

	need = calloc(n, 1);
	if (!need)
		return -1;
	mark_targets(p, n, need);
	scan_widths(p, n, &need16, &need32);

	emit_prologue(out, for_ebpf, need16, need32);

	for (pc = 0; pc < n && rc == 0; pc++) {
		const struct cbpfc_insn *i = &p[pc];

		if (need[pc])
			fprintf(out, "block_%zu:\n", pc);
		else
			fputs("    /* falls through from the previous block */\n", out);

		switch (i->code) {

		/* loads: immediate / packet length / scratch */
		case BPF_LD  | BPF_W | BPF_IMM:  fprintf(out, "    a = %uu;\n", i->k); break;
		case BPF_LDX | BPF_W | BPF_IMM:  fprintf(out, "    x = %uu;\n", i->k); break;
		case BPF_LD  | BPF_W | BPF_LEN:
			fputs("    a = (uint32_t)(data_end - data);\n", out);
			break;
		case BPF_LDX | BPF_W | BPF_LEN:
			fputs("    x = (uint32_t)(data_end - data);\n", out);
			break;

		case BPF_LD  | BPF_W | BPF_MEM:
		case BPF_LDX | BPF_W | BPF_MEM:
			if (i->k >= 16) {
				rc = -1;
				break;
			}
			fprintf(out, "    %c = m[%u];\n",
				i->code == (BPF_LD | BPF_W | BPF_MEM) ? 'a' : 'x', i->k);
			break;

		case BPF_ST:
			if (i->k >= 16) { rc = -1; break; }
			fprintf(out, "    m[%u] = a;\n", i->k);
			break;
		case BPF_STX:
			if (i->k >= 16) { rc = -1; break; }
			fprintf(out, "    m[%u] = x;\n", i->k);
			break;

		/* loads from the packet */
		case BPF_LD | BPF_W | BPF_ABS:
		case BPF_LD | BPF_H | BPF_ABS:
		case BPF_LD | BPF_B | BPF_ABS:
			emit_load(out, i->code, i->k, 0);
			break;

		case BPF_LD | BPF_W | BPF_IND:
		case BPF_LD | BPF_H | BPF_IND:
		case BPF_LD | BPF_B | BPF_IND:
			emit_load(out, i->code, i->k, 1);
			break;

		case BPF_LDX | BPF_B | BPF_MSH:                 /* ldxb 4*([k]&0xf) */
			if ((uint64_t)i->k + 1 > MAX_PKT_OFF) {
				fputs("    return 0;             /* offset exceeds 65535 */\n", out);
			} else {
				fprintf(out, "    if (data + %u > data_end) return 0;\n", i->k + 1);
				fprintf(out, "    x = ((uint32_t)data[%u] & 0x0fu) << 2;   /* IP header length */\n",
					i->k);
			}
			break;

		/* ALU */
		case BPF_ALU | BPF_ADD | BPF_K: fprintf(out, "    a += %uu;\n", i->k); break;
		case BPF_ALU | BPF_ADD | BPF_X: fputs("    a += x;\n", out); break;
		case BPF_ALU | BPF_SUB | BPF_K: fprintf(out, "    a -= %uu;\n", i->k); break;
		case BPF_ALU | BPF_SUB | BPF_X: fputs("    a -= x;\n", out); break;
		case BPF_ALU | BPF_MUL | BPF_K: fprintf(out, "    a *= %uu;\n", i->k); break;
		case BPF_ALU | BPF_MUL | BPF_X: fputs("    a *= x;\n", out); break;
		case BPF_ALU | BPF_AND | BPF_K: fprintf(out, "    a &= %uu;\n", i->k); break;
		case BPF_ALU | BPF_AND | BPF_X: fputs("    a &= x;\n", out); break;
		case BPF_ALU | BPF_OR  | BPF_K: fprintf(out, "    a |= %uu;\n", i->k); break;
		case BPF_ALU | BPF_OR  | BPF_X: fputs("    a |= x;\n", out); break;
		case BPF_ALU | BPF_XOR | BPF_K: fprintf(out, "    a ^= %uu;\n", i->k); break;
		case BPF_ALU | BPF_XOR | BPF_X: fputs("    a ^= x;\n", out); break;
		case BPF_ALU | BPF_NEG:         fputs("    a = -a;\n", out); break;

		/* Division by zero fails the whole filter. */
		case BPF_ALU | BPF_DIV | BPF_K:
			if (i->k == 0)
				fputs("    return 0;             /* divide by zero */\n", out);
			else
				fprintf(out, "    a /= %uu;\n", i->k);
			break;
		case BPF_ALU | BPF_DIV | BPF_X:
			fputs("    if (x == 0) return 0;  /* divide by zero */\n    a /= x;\n", out);
			break;
		case BPF_ALU | BPF_MOD | BPF_X:
			fputs("    if (x == 0) return 0;  /* modulo zero */\n    a %= x;\n", out);
			break;
		/* `mod #0` leaves A unchanged (libpcap semantics). */
		case BPF_ALU | BPF_MOD | BPF_K:
			if (i->k == 0)
				fputs("    /* mod #0: a unchanged */\n", out);
			else
				fprintf(out, "    a %%= %uu;\n", i->k);
			break;

		/* Shifts: the immediate form masks to 5 bits, the register form
		 * yields 0 for amounts >= 32. Both follow libpcap's bpf_filter. */
		case BPF_ALU | BPF_LSH | BPF_K: fprintf(out, "    a <<= %uu;\n", i->k & 31); break;
		case BPF_ALU | BPF_RSH | BPF_K: fprintf(out, "    a >>= %uu;\n", i->k & 31); break;
		case BPF_ALU | BPF_LSH | BPF_X: fputs("    a = (x < 32) ? (a << x) : 0;\n", out); break;
		case BPF_ALU | BPF_RSH | BPF_X: fputs("    a = (x < 32) ? (a >> x) : 0;\n", out); break;

		/* jumps: target = pc + 1 + jt/jf */
		case BPF_JMP | BPF_JA:
			emit_target(out, pc + 1 + i->k, n, "    ");
			break;

		case BPF_JMP | BPF_JEQ  | BPF_K: case BPF_JMP | BPF_JEQ  | BPF_X:
		case BPF_JMP | BPF_JGT  | BPF_K: case BPF_JMP | BPF_JGT  | BPF_X:
		case BPF_JMP | BPF_JGE  | BPF_K: case BPF_JMP | BPF_JGE  | BPF_X:
		case BPF_JMP | BPF_JSET | BPF_K: case BPF_JMP | BPF_JSET | BPF_X:
			fputs("    if (", out);
			emit_jump_cond(out, i->code, i->k);
			fputs(") ", out);
			emit_target(out, pc + 1 + i->jt, n, "");
			emit_target(out, pc + 1 + i->jf, n, "    ");
			break;

		/* return */
		case BPF_RET | BPF_K: fprintf(out, "    return %uu;\n", i->k); break;
		case BPF_RET | BPF_A: fputs("    return a;\n", out); break;

		/* register moves */
		case BPF_MISC | BPF_TAX: fputs("    x = a;\n", out); break;
		case BPF_MISC | BPF_TXA: fputs("    a = x;\n", out); break;

		default:
			rc = -1;
			break;
		}
	}

	if (rc == 0) {
		fputs("\n    return 0;                 /* ran off the end = no match */\n"
		      "}\n", out);

		if (for_ebpf) {
			/* Wrap in a TC classifier. cBPF's return value is "bytes to
			 * keep", so non-zero means the filter matched. */
			fputs("\nSEC(\"tc\")\n"
			      "int cbpf_filter(struct __sk_buff *skb)\n"
			      "{\n"
			      "    void *data     = (void *)(long)skb->data;\n"
			      "    void *data_end = (void *)(long)skb->data_end;\n"
			      "\n"
			      "    /* Non-zero means matched -> let it through. */\n"
			      "    return filter(data, data_end) ? TC_ACT_OK : TC_ACT_SHOT;\n"
			      "}\n"
			      "\nchar _license[] SEC(\"license\") = \"GPL\";\n", out);
		}
	}

	free(need);
	return rc;
}

/**
 * cbpfc_to_c:
 * @out: where to write the C source
 * @prog: the cBPF program
 * @n: number of instructions in @prog
 * @for_ebpf: 1 to emit a form `clang -target bpf` accepts (the function is
 *            inlined at the call site and <linux/bpf.h> is included), 0 for
 *            plain user space C
 *
 * Emits a C function
 *
 *	uint32_t filter(const uint8_t *data, const uint8_t *data_end)
 *
 * returning the cBPF return value: 0 if the packet does not match, non-zero if
 * it does.
 *
 * Returns: 0 on success, -1 if @prog holds an instruction this compiler does
 * not handle
 */
int cbpfc_to_c(FILE *out, const struct cbpfc_insn *prog, size_t n, int for_ebpf)
{
	return translate(out, prog, n, for_ebpf);
}
