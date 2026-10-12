/*
 * pcap_writer.h - write captured packets to a pcap file.
 *
 * Kept behind an opaque handle so that <pcap.h> stays out of xdpdump.c:
 * <pcap.h> and <linux/bpf.h> both define `struct bpf_insn`.
 */
#ifndef PCAP_WRITER_H
#define PCAP_WRITER_H

#include <stdint.h>

struct pcap_writer;

struct pcap_writer *pcap_writer_open(const char *path);

/* Why the last call failed - an empty string if it did not. Same shape as
 * cbpfc_errmsg(); read it straight after the call. */
const char *pcap_writer_errmsg(void);
void pcap_writer_write(struct pcap_writer *w, const uint8_t *data,
		       uint32_t caplen, uint32_t len);
void pcap_writer_close(struct pcap_writer *w);

#endif
