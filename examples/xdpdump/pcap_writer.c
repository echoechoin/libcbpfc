/*
 * pcap_writer.c - write captured packets to a pcap file.
 *
 * The libpcap side of xdpdump, kept in its own translation unit so that
 * <pcap.h> does not meet <linux/bpf.h> in the rest of the tool.
 */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include "pcap_writer.h"

struct pcap_writer {
	pcap_dumper_t *dump;
};

struct pcap_writer *pcap_writer_open(const char *path, char *err, size_t errsz)
{
	struct pcap_writer *w = calloc(1, sizeof(*w));
	pcap_t *dead;

	if (!w)
		return NULL;

	/* A "dead" handle just describes the link type; no capture happens. */
	dead = pcap_open_dead(DLT_EN10MB, 65535);
	if (!dead) {
		free(w);
		return NULL;
	}

	w->dump = pcap_dump_open(dead, path);
	pcap_close(dead);
	if (!w->dump) {
		if (err)
			snprintf(err, errsz, "cannot open %s", path);
		free(w);
		return NULL;
	}
	return w;
}

void pcap_writer_write(struct pcap_writer *w, const uint8_t *data,
		       uint32_t caplen, uint32_t len)
{
	struct pcap_pkthdr hdr;

	/* The kernel side does not stamp the packet, so the time it reached
	 * user space is recorded instead. */
	gettimeofday(&hdr.ts, NULL);
	hdr.caplen = caplen;
	hdr.len    = len;
	pcap_dump((u_char *)w->dump, &hdr, data);
}

void pcap_writer_close(struct pcap_writer *w)
{
	if (!w)
		return;
	if (w->dump)
		pcap_dump_close(w->dump);
	free(w);
}
