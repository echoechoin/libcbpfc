/*
 * common.h - shared test helpers.
 *
 * The packet corpus every test runs against, and libpcap's interpreter, which
 * provides the reference result they are compared with.
 */
#ifndef CBPFC_TEST_COMMON_H
#define CBPFC_TEST_COMMON_H

#include <stddef.h>
#include <stdint.h>

#define PKT_MAX 512

/* Filter expressions exercised by every test. */
extern const char *const cbpf_test_exprs[];
extern const int cbpf_test_expr_count;

/* Deterministic packet generator.
 *
 * Packet i is derived only from i, so every test sees the same corpus
 * regardless of the order it iterates in. The body is filled with random
 * bytes first, which drives the bounds-check paths, and then a few fields are
 * overwritten to produce packets that actually match something.
 *
 * Returns the packet length (always at least ETH_HLEN: TC classifies real
 * frames, so shorter packets cannot occur and BPF_PROG_TEST_RUN rejects
 * them).
 */
size_t cbpf_test_packet(int i, uint8_t *pkt);

/* How many packets the corpus contains. */
#define PKT_COUNT 200

/* libpcap's interpreter, the reference result.
 *
 * This lives here rather than next to its users because <pcap.h> and
 * <linux/bpf.h> both define `struct bpf_insn`, so a translation unit that
 * includes <bpf/libbpf.h> cannot also include <pcap.h>. Keeping the pcap
 * dependency in this file leaves the tests free to use libbpf. */
struct cbpfc_insn;

uint32_t cbpf_libpcap_filter(const struct cbpfc_insn *prog,
			     const uint8_t *pkt, size_t len);

#endif
