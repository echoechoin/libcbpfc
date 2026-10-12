/*
 * internal.h - shared between the library's translation units, not installed.
 */
#ifndef CBPFC_INTERNAL_H
#define CBPFC_INTERNAL_H

#include <stdint.h>

/* The cBPF opcode encoding. bpf_common.h and not bpf.h on purpose: the former
 * is macros only, while the latter also defines `struct bpf_insn`, which is
 * exactly what the pcap side of the library must not meet. */
#include <linux/bpf_common.h>

/* The verifier only accepts packet offsets that fit in 16 bits; a load beyond
 * that can never match, so both backends turn it into "no match". */
#define MAX_PKT_OFF 0xFFFF

/* How many bytes a load reads, taken from the size field of its code: BPF_W,
 * BPF_H or BPF_B. Both backends need this to decode a packet load, so it is
 * here rather than in two copies. */
static inline int width_bytes(uint16_t code)
{
	switch (code & 0x18) {
	case BPF_W: return 4;
	case BPF_H: return 2;
	default:    return 1;           /* BPF_B */
	}
}

/* Record the message cbpfc_errmsg() returns. Every public entry point that can
 * fail clears it first, so what comes back is always from the call that just
 * failed. */
void cbpfc_err_set(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

void cbpfc_err_clear(void);

#endif /* CBPFC_INTERNAL_H */
