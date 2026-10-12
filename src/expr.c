/*
 * expr.c - compile a tcpdump-style filter expression to cBPF with libpcap.
 *
 * Kept in its own translation unit: <pcap.h> and <linux/bpf.h> both define
 * `struct bpf_insn`, so anything that touches pcap stays here and the rest of
 * the library only sees the opaque struct cbpfc_expr.
 */
#include <stdlib.h>
#include <string.h>

#include <pcap.h>

#include "cbpfc.h"
#include "internal.h"

struct cbpfc_expr {
	struct cbpfc_insn *insns;
	size_t             n;
};

/**
 * cbpfc_expr_new:
 * @expr: a tcpdump-style filter expression
 *
 * Compiles @expr with libpcap. The resulting cBPF program is what
 * cbpfc_to_c(), cbpfc_to_ebpf() and cbpfc_inject() take.
 *
 * Returns: a new expression, or NULL on failure - see cbpfc_errmsg()
 */
struct cbpfc_expr *cbpfc_expr_new(const char *expr)
{
	struct cbpfc_expr *e;
	struct bpf_program fp;          /* libpcap's copy, alive for one compile */
	pcap_t *dead;

	cbpfc_err_clear();

	e = calloc(1, sizeof(*e));
	if (!e) {
		cbpfc_err_set("out of memory");
		return NULL;
	}

	dead = pcap_open_dead(DLT_EN10MB, 262144);
	if (!dead) {
		cbpfc_err_set("pcap_open_dead failed");
		free(e);
		return NULL;
	}

	if (pcap_compile(dead, &fp, expr, 1, PCAP_NETMASK_UNKNOWN) < 0) {
		cbpfc_err_set("%s", pcap_geterr(dead));
		pcap_close(dead);
		free(e);
		return NULL;
	}

	/* The handle exists only to carry the error message above. */
	pcap_close(dead);

	e->n = fp.bf_len;
	e->insns = calloc(e->n ? e->n : 1, sizeof(*e->insns));
	if (!e->insns) {
		cbpfc_err_set("out of memory");
		pcap_freecode(&fp);
		free(e);
		return NULL;
	}

	/* pcap's struct bpf_insn and our cbpfc_insn have identical layouts, so
	 * this is a plain copy - and after it, libpcap's array is not needed. */
	memcpy(e->insns, fp.bf_insns, e->n * sizeof(*e->insns));
	pcap_freecode(&fp);
	return e;
}

/**
 * cbpfc_expr_insns:
 * @e: the expression
 * @n: returns the number of instructions
 *
 * The instructions belong to @e and stay valid until cbpfc_expr_free().
 *
 * Returns: the cBPF program libpcap produced for @e
 */
const struct cbpfc_insn *cbpfc_expr_insns(const struct cbpfc_expr *e, size_t *n)
{
	*n = e->n;
	return e->insns;
}

/**
 * cbpfc_expr_bpf_filter:
 * @e: the expression
 * @pkt: the packet to run it against
 * @len: length of @pkt
 *
 * Runs libpcap's own interpreter over @pkt - the reference result the
 * generated C and eBPF are expected to match. It lives here rather than in the
 * caller because <pcap.h> and <linux/bpf.h> both define `struct bpf_insn` and
 * cannot be included in one translation unit.
 *
 * Returns: the cBPF return value for @pkt - 0 if it does not match
 */
uint32_t cbpfc_expr_bpf_filter(const struct cbpfc_expr *e,
			       const uint8_t *pkt, size_t len)
{
	/* libpcap's interpreter, run on our copy of the program. */
	return bpf_filter((const struct bpf_insn *)e->insns, pkt,
			  (unsigned)len, (unsigned)len);
}

/**
 * cbpfc_expr_free:
 * @e: the expression to release, or NULL
 *
 * Releases @e and the instructions it holds.
 */
void cbpfc_expr_free(struct cbpfc_expr *e)
{
	if (!e)
		return;
	free(e->insns);
	free(e);
}
