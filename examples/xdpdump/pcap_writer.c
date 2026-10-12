/*
 * pcap_writer.c - write captured packets to a pcap file.
 *
 * The libpcap side of xdpdump, kept in its own translation unit so that
 * <pcap.h> does not meet <linux/bpf.h> in the rest of the tool.
 */
#include <pcap.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include "pcap_writer.h"

struct pcap_writer {
	pcap_dumper_t *dump;
};

/* Same shape as the library's error reporting: a fixed per-thread message
 * behind an accessor, so the caller keeps no buffer. */
static _Thread_local char last[256];

static void report(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(last, sizeof(last), fmt, ap);
	va_end(ap);
}

struct pcap_writer *pcap_writer_open(const char *path)
{
	struct pcap_writer *w;
	pcap_t *dead;

	last[0] = '\0';

	w = calloc(1, sizeof(*w));
	if (!w) {
		report("out of memory");
		return NULL;
	}

	/* A "dead" handle just describes the link type; no capture happens. */
	dead = pcap_open_dead(DLT_EN10MB, 65535);
	if (!dead) {
		report("pcap_open_dead failed");
		free(w);
		return NULL;
	}

	w->dump = pcap_dump_open(dead, path);
	pcap_close(dead);
	if (!w->dump) {
		report("cannot open %s", path);
		free(w);
		return NULL;
	}
	return w;
}

const char *pcap_writer_errmsg(void)
{
	return last;
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
