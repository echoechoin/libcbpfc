/*
 * pcap_writer.h - write captured packets to a pcap file.
 *
 * Kept behind an opaque handle so that <pcap.h> stays out of xdpdump.c:
 * <pcap.h> and <linux/bpf.h> both define `struct bpf_insn`.
 */
#ifndef PCAP_WRITER_H
#define PCAP_WRITER_H

#include <stddef.h>
#include <stdint.h>

struct pcap_writer;

struct pcap_writer *pcap_writer_open(const char *path, char *err, size_t errsz);
void pcap_writer_write(struct pcap_writer *w, const uint8_t *data,
		       uint32_t caplen, uint32_t len);
void pcap_writer_close(struct pcap_writer *w);

#endif
