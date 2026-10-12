/*
 * cbpfc.h - classic BPF (cBPF) to eBPF / C compiler.
 *
 * A filter comes in as a tcpdump-style expression, compiled by libpcap (see
 * cbpfc_expr_new()), or as a cBPF program the caller already has. It goes out
 * as C source, as an eBPF fragment or as a bpf_object loaded by libbpf.
 */
#ifndef CBPFC_H
#define CBPFC_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * cbpfc_insn:
 *
 * A classic BPF instruction. The layout is the same as pcap's struct bpf_insn,
 * so a program compiled by libpcap can be used as is.
 */
struct cbpfc_insn {
	uint16_t code;
	uint8_t  jt;
	uint8_t  jf;
	uint32_t k;
};

/**
 * cbpfc_ebpf_insn:
 *
 * An eBPF instruction. The layout has to match the kernel's struct bpf_insn
 * (8 bytes), because an array of these goes to bpf(BPF_PROG_LOAD) untouched.
 */
struct cbpfc_ebpf_insn {
	uint8_t  code;
	uint8_t  dst_reg:4;
	uint8_t  src_reg:4;
	int16_t  off;
	int32_t  imm;
};

/**
 * cbpfc_ebpf_prog:
 *
 * A compiled eBPF fragment: @insn holds @n instructions. The memory belongs to
 * the struct - release it with cbpfc_ebpf_prog_free().
 */
struct cbpfc_ebpf_prog {
	struct cbpfc_ebpf_insn *insn;
	size_t                  n;
};

/**
 * cbpfc_expr:
 *
 * A filter expression compiled to cBPF by libpcap. Opaque: reach the
 * instructions with cbpfc_expr_insns() and release it with cbpfc_expr_free().
 */
struct cbpfc_expr;

struct bpf_object;      /* libbpf's, so this header stays standalone */

int cbpfc_to_c(FILE *out, const struct cbpfc_insn *prog, size_t n, int for_ebpf);

int cbpfc_to_ebpf(const struct cbpfc_insn *prog, size_t n,
		  struct cbpfc_ebpf_prog *out);

void cbpfc_ebpf_prog_free(struct cbpfc_ebpf_prog *p);

void cbpfc_disasm(char *buf, size_t bufsz, const struct cbpfc_ebpf_insn *in);

struct cbpfc_expr *cbpfc_expr_new(const char *expr, char *err, size_t errsz);

const struct cbpfc_insn *cbpfc_expr_insns(const struct cbpfc_expr *e, size_t *n);

uint32_t cbpfc_expr_bpf_filter(const struct cbpfc_expr *e,
			       const uint8_t *pkt, size_t len);

void cbpfc_expr_free(struct cbpfc_expr *e);

struct bpf_object *cbpfc_inject(const char *path, const char *func_name,
				const struct cbpfc_insn *prog, size_t n,
				char *err, size_t errsz);

#ifdef __cplusplus
}
#endif

#endif /* CBPFC_H */
