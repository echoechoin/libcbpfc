/*
 * skeleton.c - the host eBPF program.
 *
 * Compiled once, ahead of time, into skeleton.o. At run time only that object
 * is needed - no clang on the target machine. This mirrors how pwru ships
 * kprobepwru_arm64_bpfel.o and injects the user's filter into it.
 *
 * filter_pcap() is the placeholder: cbpfc_inject() puts the compiled filter in
 * front of its body. The two helpers around it are not decoration - they sit in
 * .text on either side of the placeholder, so that every test run exercises the
 * records cbpfc_inject() has to move when the placeholder grows: the symbol of
 * the function after it, the call that reaches that function, and its
 * .BTF.ext entries. test_ebpf checks the layout is still the one described
 * here; without that check a compiler change could quietly stop covering it.
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

/* Both helpers are false for a real packet, so the verdict stays filter_pcap's.
 *
 * They are noinline on purpose - that is what puts them in .text rather than
 * inlining them away. clang lays .text out in call order, so tc_filter calls
 * them in the order they are wanted in: before_helper, filter_pcap,
 * after_helper. */
__attribute__((noinline))
static unsigned int before_helper(void *data, void *data_end)
{
	return data > data_end;
}

/*
 * The placeholder. The five parameters fix the register contract of the
 * BPF-to-BPF calling convention:
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

__attribute__((noinline))
static unsigned int after_helper(void *data, void *data_end)
{
	return data > data_end;
}

SEC("tc")
int tc_filter(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	unsigned int r;

	r  = before_helper(data, data_end);
	r |= filter_pcap(data, data, data, data, data_end);
	r |= after_helper(data, data_end);

	return r ? TC_ACT_OK : TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
