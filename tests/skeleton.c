/*
 * skeleton.c - the host eBPF program.
 *
 * Compiled once, ahead of time, into skeleton.o. At run time only that object
 * is needed - no clang on the target machine. This mirrors how pwru ships
 * kprobepwru_arm64_bpfel.o and injects the user's filter into it.
 *
 * filter_pcap() is the placeholder: cbpfc_inject() replaces the beginning of
 * its body with the compiled filter.
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

/* The five parameters fix the register contract of the BPF-to-BPF calling
 * convention:
 *
 *     _a -> r1   __b -> r2   __c -> r3    scratch, free for the injected code
 *     data -> r4                          packet start
 *     data_end -> r5                      packet end
 *
 * The body doubles as the result converter: the injected fragment writes its
 * result into r4 and zeroes r5/r1/r2/r3, so `data != data_end` becomes
 * "result != 0". With no filter injected the caller passes real pointers and
 * the expression degrades to "the packet is non-empty".
 */
__attribute__((noinline))
static unsigned int filter_pcap(void *_a, void *__b, void *__c, void *data, void *data_end)
{
	return (data != data_end) && (_a == __b) && (__b == __c);
}

SEC("tc")
int tc_filter(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	return filter_pcap(data, data, data, data, data_end) ? TC_ACT_OK : TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
