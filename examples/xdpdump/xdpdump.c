/*
 * xdpdump.c - dump packets matching a tcpdump-style filter into a pcap file.
 *
 *     sudo ./xdpdump -i eth0 -n 100 "udp and port 53"
 *
 * The filter expression is compiled by libpcap to cBPF, translated to an eBPF
 * fragment and spliced into xdpdump.bpf.o, which holds the XDP program and
 * the filter_pcap placeholder. cbpfc_inject() hands back a loaded libbpf
 * object; the program is attached to the interface and matching packets are
 * pushed through the host's ring buffer into a pcap file until the requested
 * count is reached. Nothing is ever dropped - the program returns XDP_PASS for
 * every packet, so the interface keeps working normally.
 *
 * Needs root: loading and attaching an XDP program requires CAP_BPF.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <net/ethernet.h>          /* ETH_P_ALL */
#include <net/if.h>
#include <netpacket/packet.h>      /* struct packet_mreq, PACKET_MR_PROMISC */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/if_link.h>          /* XDP_FLAGS_* */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cbpfc.h"
#include "pcap_writer.h"
#include "xdpdump_event.h"

/* The program in xdpdump.bpf.c, and the map it pushes events through. */
#define HOST_PROG  "xdp_dump"
#define HOST_EVENTS "events"

#ifndef XDPDUMP_DEFAULT_OBJ
#define XDPDUMP_DEFAULT_OBJ "xdpdump.bpf.o"
#endif

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
	g_stop = 1;
	signal(sig, SIG_DFL);
}

struct capture {
	struct pcap_writer *out;
	unsigned long       captured;
	unsigned long       limit;
	int                 verbose;
};

static int on_event(void *user, void *data, size_t len)
{
	struct capture *c = user;
	const struct xdpdump_event *e = data;

	if (len < sizeof(*e))
		return 0;

	c->captured++;
	pcap_writer_write(c->out, e->data, e->caplen, e->len);

	if (c->verbose && e->caplen >= 34)
		printf("  #%lu  len=%u caplen=%u\n", c->captured, e->len, e->caplen);
	return 0;
}

static int promiscuous_on(int ifindex)
{
	struct packet_mreq mr = {
		.mr_ifindex = ifindex,
		.mr_type    = PACKET_MR_PROMISC,
	};
	int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));

	if (fd < 0)
		return -1;
	if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s -i <iface> -n <count> [options] '<filter expression>'\n"
		"\n"
		"  -i, --iface <iface>    interface to capture on (required)\n"
		"  -n, --count <n>        stop after capturing n packets (required)\n"
		"  -w, --write <file>     output pcap file (default: xdpdump.pcap)\n"
		"  -o, --object <file>    compiled XDP host object\n"
		"                         (default: %s)\n"
		"  -D, --drv              attach in native XDP mode instead of generic\n"
		"  -p, --no-promisc       do not put the interface into promiscuous mode\n"
		"  -t, --timeout <sec>    give up after this long (default: no limit)\n"
		"  -v, --verbose          print one line per captured packet\n"
		"\n"
		"example:\n"
		"  sudo %s -i eth0 -n 100 'udp and port 53' -w dns.pcap\n",
		argv0, XDPDUMP_DEFAULT_OBJ, argv0);
}

int main(int argc, char **argv)
{
	const char *iface = NULL, *outfile = "xdpdump.pcap";
	const char *objpath = XDPDUMP_DEFAULT_OBJ;
	const char *expr = NULL;
	unsigned long limit = 0;
	int   timeout = 0, drv_mode = 0, verbose = 0, no_promisc = 0;
	int   ifindex, prog_fd = -1, events_fd = -1, promisc_fd = -1, link_fd = -1;
	__u32 xdp_flags;
	struct cbpfc_expr *e = NULL;
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct ring_buffer *rb = NULL;
	struct capture cap;
	struct pcap_writer *out = NULL;
	time_t started;
	int    rc = 1, opt;

	/* line buffered: output stays readable when redirected */
	setvbuf(stdout, NULL, _IOLBF, 0);

	static const struct option long_opts[] = {
		{ "iface",   required_argument, NULL, 'i' },
		{ "count",   required_argument, NULL, 'n' },
		{ "write",   required_argument, NULL, 'w' },
		{ "object",  required_argument, NULL, 'o' },
		{ "drv",     no_argument,       NULL, 'D' },
		{ "no-promisc", no_argument,    NULL, 'p' },
		{ "timeout", required_argument, NULL, 't' },
		{ "verbose", no_argument,       NULL, 'v' },
		{ "help",    no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	while ((opt = getopt_long(argc, argv, "i:n:w:o:Dpt:vh", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'i': iface   = optarg; break;
		case 'n': limit   = strtoul(optarg, NULL, 10); break;
		case 'w': outfile = optarg; break;
		case 'o': objpath = optarg; break;
		case 'D': drv_mode = 1; break;
		case 'p': no_promisc = 1; break;
		case 't': timeout = atoi(optarg); break;
		case 'v': verbose = 1; break;
		case 'h': usage(argv[0]); return 0;
		default:  usage(argv[0]); return 2;
		}
	}

	if (optind < argc)
		expr = argv[optind];

	if (!iface || !expr || limit == 0) {
		usage(argv[0]);
		return 2;
	}
	if (geteuid() != 0) {
		fprintf(stderr, "xdpdump: needs root (CAP_BPF)\n");
		return 1;
	}

	ifindex = (int)if_nametoindex(iface);
	if (!ifindex) {
		fprintf(stderr, "no such interface: %s\n", iface);
		return 1;
	}

	/* 1. filter expression -> cBPF */
	e = cbpfc_expr_new(expr);
	if (!e) {
		fprintf(stderr, "bad filter expression: %s\n", cbpfc_errmsg());
		return 1;
	}

	/* 2. replace filter_pcap in the host object and load it */
	{
		size_t n;
		const struct cbpfc_insn *insns = cbpfc_expr_insns(e, &n);

		obj = cbpfc_inject(objpath, "filter_pcap", insns, n);
		if (!obj) {
			fprintf(stderr, "cannot inject the filter: %s\n", cbpfc_errmsg());
			goto out;
		}
	}

	/* 3. pick up the program and the host's ring buffer */
	prog = bpf_object__find_program_by_name(obj, HOST_PROG);
	if (!prog) {
		fprintf(stderr, "no program named \"%s\" in %s\n", HOST_PROG, objpath);
		goto out_obj;
	}
	prog_fd = bpf_program__fd(prog);        /* owned by the object */

	{
		struct bpf_map *m = bpf_object__find_map_by_name(obj, HOST_EVENTS);

		if (!m) {
			fprintf(stderr, "no map named \"%s\" in %s\n", HOST_EVENTS, objpath);
			goto out_obj;
		}
		events_fd = bpf_map__fd(m);
	}

	/* 4. promiscuous mode, then attach */
	if (!no_promisc) {
		promisc_fd = promiscuous_on(ifindex);
		if (promisc_fd < 0)
			fprintf(stderr, "warning: %s is not in promiscuous mode: %s\n",
				iface, strerror(errno));
	}

	xdp_flags = drv_mode ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
	{
		struct bpf_link_create_opts lc = {
			.sz    = sizeof(lc),
			.flags = xdp_flags,
		};

		link_fd = bpf_link_create(prog_fd, ifindex, BPF_XDP, &lc);
	}
	if (link_fd < 0) {
		fprintf(stderr, "cannot attach XDP to %s: %s\n", iface, strerror(errno));
		if (errno == EBUSY)
			fprintf(stderr, "  another program is attached;"
					" `ip link set dev %s xdp off` clears it\n", iface);
		goto out_obj;
	}

	out = pcap_writer_open(outfile);
	if (!out) {
		fprintf(stderr, "%s\n", pcap_writer_errmsg());
		goto out_detach;
	}

	rb = ring_buffer__new(events_fd, on_event, &cap, NULL);
	if (!rb) {
		fprintf(stderr, "cannot create the ring buffer: %s\n", strerror(errno));
		goto out_detach;
	}

	cap.out      = out;
	cap.captured = 0;
	cap.limit    = limit;
	cap.verbose  = verbose;

	printf("capturing on %s (%s mode%s)  filter: %s\n",
	       iface, drv_mode ? "native" : "generic",
	       promisc_fd >= 0 ? ", promiscuous" : "", expr);
	printf("stopping after %lu packets, writing to %s   (Ctrl+C to stop)\n",
	       limit, outfile);

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	/* 5. collect */
	started = time(NULL);
	while (!g_stop && cap.captured < limit) {
		int n = ring_buffer__poll(rb, 200);

		if (n < 0 && n != -EINTR) {
			fprintf(stderr, "ring buffer error: %s\n", strerror(-n));
			break;
		}
		if (timeout > 0 && time(NULL) - started >= timeout)
			break;
	}

	printf("captured %lu packet%s\n", cap.captured,
	       cap.captured == 1 ? "" : "s");
	rc = 0;

out_detach:
	/* Closing the link detaches the program. The kernel does this for us if
	 * we are killed, which is the point of attaching through a link. */
	if (link_fd >= 0)
		close(link_fd);
out_obj:
	/* The ring buffer holds a dup of the map fd, but tear it down first so
	 * the order does not depend on that. prog_fd and events_fd belong to the
	 * object: closing it closes them. */
	if (rb) {
		ring_buffer__free(rb);
		rb = NULL;
	}
	bpf_object__close(obj);
out:
	/* Closing this drops the promiscuous membership the kernel is counting
	 * for us - which it also does if we are killed. */
	if (promisc_fd >= 0)
		close(promisc_fd);
	pcap_writer_close(out);
	cbpfc_expr_free(e);
	return rc;
}
