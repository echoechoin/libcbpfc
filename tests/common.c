/*
 * common.c - the packet corpus and the libpcap reference interpreter, shared
 * by the tests.
 *
 * The pcap dependency lives here rather than next to its users because
 * <pcap.h> and <linux/bpf.h> both define `struct bpf_insn`, so a translation
 * unit that includes <bpf/libbpf.h> cannot also include <pcap.h>.
 */
#include <pcap.h>
#include <string.h>

#include "cbpfc.h"
#include "common.h"

const char *const cbpf_test_exprs[] = {
	"udp and port 53", "tcp", "icmp", "icmp6", "ip", "ip6", "arp",
	"udp port 67 or udp port 68", "host 192.168.1.1", "net 10.0.0.0/8",
	"tcp[tcpflags] & tcp-syn != 0", "udp and (port 53 or port 123)",
	"greater 100", "less 60", "vlan 100", "ether[0] & 1 = 0",
	"ip[6:2] & 0x1fff = 0", "dst portrange 100-200",
	"src host 10.1.2.3 and dst port 80", "port 443 or port 80",
	"host 2001:db8::1", "udp[10] & 0x80 != 0", "ip proto \\tcp",
	"ip[0] & 0xf > 5", "ether[12:2] = 0x86dd", "tcp port 80",
};
const int cbpf_test_expr_count =
	(int)(sizeof(cbpf_test_exprs) / sizeof(cbpf_test_exprs[0]));

static uint64_t rnd_state;

static void rnd_seed(uint64_t s)
{
	rnd_state = s;
}

uint32_t cbpf_rand(uint64_t *state)
{
	*state = *state * 6364136223846793005ULL + 1442695040888963407ULL;
	return (uint32_t)(*state >> 33);
}

static unsigned rnd(void)
{
	return cbpf_rand(&rnd_state);
}

size_t cbpf_test_packet(int i, uint8_t *pkt)
{
	int kind, len;

	/* Seeding from the index keeps the corpus stable across tests. */
	rnd_seed(12345u + (uint64_t)i);

	len  = 14 + (int)(rnd() % 146);         /* 14..159 */
	kind = i % 8;

	for (int j = 0; j < len; j++)
		pkt[j] = (uint8_t)rnd();

	switch (kind) {
	case 1:                                 /* IPv4 / UDP, port 53 */
		if (len < 42) break;
		pkt[12]=0x08; pkt[13]=0x00; pkt[14]=0x45; pkt[23]=17;
		pkt[26]=192; pkt[27]=168; pkt[28]=1; pkt[29]=1;
		pkt[30]=8; pkt[31]=8; pkt[32]=8; pkt[33]=8;
		pkt[34]=0x00; pkt[35]=53; pkt[36]=0x00; pkt[37]=53;
		pkt[20]=0; pkt[21]=0;
		break;
	case 2:                                 /* IPv4 / TCP SYN to port 80 */
		if (len < 48) break;
		pkt[12]=0x08; pkt[13]=0x00; pkt[14]=0x45; pkt[23]=6;
		pkt[26]=10; pkt[27]=1; pkt[28]=2; pkt[29]=3;
		pkt[34]=0x30; pkt[35]=0x39; pkt[36]=0x00; pkt[37]=0x50;
		pkt[46]=0x50; pkt[47]=0x02;
		pkt[20]=0; pkt[21]=0;
		break;
	case 3:                                 /* IPv6 / UDP, port 53 */
		if (len < 58) break;
		pkt[12]=0x86; pkt[13]=0xdd; pkt[14]=0x60; pkt[20]=17;
		pkt[54]=0x00; pkt[55]=53; pkt[56]=0x00; pkt[57]=53;
		break;
	case 4:                                 /* IPv4 with 4 bytes of options */
		if (len < 40) break;
		pkt[12]=0x08; pkt[13]=0x00; pkt[14]=0x46; pkt[23]=17;
		pkt[20]=0; pkt[21]=0;
		pkt[38]=0x00; pkt[39]=53;
		break;
	case 5:                                 /* IPv4 fragment, offset != 0 */
		if (len < 34) break;
		pkt[12]=0x08; pkt[13]=0x00; pkt[14]=0x45; pkt[23]=17;
		pkt[20]=0x00; pkt[21]=0x08;
		break;
	case 6:                                 /* IPv4 / ICMP echo request */
		if (len < 42) break;
		pkt[12]=0x08; pkt[13]=0x00; pkt[14]=0x45; pkt[23]=1;
		pkt[34]=0x08;
		pkt[20]=0; pkt[21]=0;
		break;
	case 7:                                 /* VLAN 100 + IPv4/UDP, port 53 */
		if (len < 60) break;
		pkt[12]=0x81; pkt[13]=0x00;         /* 802.1Q */
		pkt[14]=0x00; pkt[15]=0x64;         /* VLAN id 100 */
		pkt[16]=0x08; pkt[17]=0x00;         /* inner ethertype: IPv4 */
		pkt[18]=0x45; pkt[27]=17;
		pkt[24]=0; pkt[25]=0;
		pkt[38]=0x00; pkt[39]=53; pkt[40]=0x00; pkt[41]=53;
		break;
	default:
		break;                          /* pure random bytes */
	}

	return (size_t)len;
}

/* libpcap's interpreter, the reference result. struct cbpfc_insn and pcap's
 * struct bpf_insn have identical layouts, so only the pointer type differs. */
uint32_t cbpf_libpcap_filter(const struct cbpfc_insn *prog,
			     const uint8_t *pkt, size_t len)
{
	return bpf_filter((const struct bpf_insn *)prog, pkt,
			  (unsigned)len, (unsigned)len);
}
