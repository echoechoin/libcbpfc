/*
 * xdpdump.bpf.c - the XDP host program.
 *
 * Compiled once, at build time, into xdpdump.bpf.o. filter_pcap() is a
 * placeholder: cbpfc_inject() replaces the beginning of its body with the
 * compiled filter at run time, so the target machine never needs clang.
 * Everything else - the ring buffer, the packet counter, passing traffic
 * through - is fixed here.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "xdpdump_event.h"

#define SNAPLEN XDPDUMP_SNAPLEN

/* Snapshot granularity. */
#define CHUNK 16

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

/* Placeholder. The five parameters fix the register contract of the BPF-to-BPF
 * calling convention:
 *
 *     _a -> r1   __b -> r2   __c -> r3    scratch, free for the fragment
 *     data -> r4                          packet start
 *     data_end -> r5                      packet end
 *
 * The body is the result converter: the injected fragment writes its result
 * into r4 and zeroes r5/r1/r2/r3, so this evaluates to "result != 0". Without
 * a filter injected the caller passes real pointers and the expression
 * degrades to "the packet is non-empty".
 */
__attribute__((noinline))
static unsigned int filter_pcap(void *_a, void *__b, void *__c,
				void *data, void *data_end)
{
	return (data != data_end) && (_a == __b) && (__b == __c);
}

SEC("xdp")
int xdp_dump(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct xdpdump_event *e;

	/* The injected filter decides. This is a capture tool, so the packet is
	 * never dropped - it always continues up the stack.
	 *
	 * There is no counter here: the ring buffer is the only map, and user
	 * space stops reading once it has enough packets. Sending a few extra
	 * records before it detaches costs nothing. */
	if (!filter_pcap(data, data, data, data, data_end))
		return XDP_PASS;

	/* reserve() takes a compile-time constant size, so always reserve the
	 * maximum and record how much of it is real. */
	e = bpf_ringbuf_reserve(&events, sizeof(*e) + SNAPLEN, 0);
	if (!e)
		return XDP_PASS;

	e->len    = (__u32)((long)data_end - (long)data);

	/* Snapshot the packet in fixed-size chunks.
	 *
	 * bpf_xdp_load_bytes() would take a variable length, but its size
	 * argument is ARG_CONST_SIZE: the verifier has to prove the length is
	 * non-zero and inside the destination, and clang folds away every guard
	 * that would tell it so - it knows the length is just `data_end - data`
	 * and rewrites the test into a pointer comparison. A run of fixed-size
	 * copies compiles into plain packet bound checks instead, which the
	 * verifier always accepts. caplen ends up as the packet length rounded
	 * down to a multiple of CHUNK. */
	e->caplen = 0;
	for (int i = 0; i < SNAPLEN / CHUNK; i++) {
		const __u32 off = (__u32)i * CHUNK;

		if (data + off + CHUNK > data_end)
			break;
		__builtin_memcpy(e->data + off, (const __u8 *)data + off, CHUNK);
		e->caplen = off + CHUNK;
	}

	/* A packet we could not snapshot at all is not worth reporting. */
	if (e->caplen == 0) {
		bpf_ringbuf_discard(e, 0);
		return XDP_PASS;
	}

	bpf_ringbuf_submit(e, 0);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
