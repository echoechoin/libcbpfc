/*
 * xdpdump_event.h - the ring buffer record, shared by the XDP program and the
 * user space tool.
 */
#ifndef XDPDUMP_EVENT_H
#define XDPDUMP_EVENT_H

#include <linux/types.h>

/* How much of each packet is copied to user space. */
#define XDPDUMP_SNAPLEN 128

struct xdpdump_event {
	__u32 len;            /* full packet length on the wire */
	__u32 caplen;         /* bytes actually captured in data[] */
	__u8  data[];         /* packet snapshot, at most XDPDUMP_SNAPLEN bytes */
};

#endif
