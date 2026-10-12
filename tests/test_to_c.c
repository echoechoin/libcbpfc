/*
 * test_to_c.c - compile the generated C and compare it with libpcap.
 *
 * For every filter expression the emitted C is written to a temporary file,
 * built into a shared object and loaded with dlopen, so it can be called like
 * any other function. No eBPF, no root: the generated code is ordinary C.
 */
#include <dlfcn.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cbpfc.h"
#include "common.h"

typedef uint32_t (*filter_fn)(const uint8_t *, const uint8_t *);

struct built {
	void      *handle;
	filter_fn  fn;
	char       so[128];
};

static int build(const struct cbpfc_insn *prog, size_t n, struct built *b)
{
	static int seq;
	char       csrc[128], cmd[512];
	FILE      *f;
	const char *cc = getenv("CC") ? getenv("CC") : "cc";

	snprintf(csrc, sizeof(csrc), "/tmp/cbpfc_tc_%d_%d.c", (int)getpid(), seq);
	snprintf(b->so, sizeof(b->so), "/tmp/cbpfc_tc_%d_%d.so", (int)getpid(), seq);
	seq++;

	f = fopen(csrc, "w");
	if (!f)
		return -1;
	if (cbpfc_to_c(f, prog, n, 0) != 0) {
		fclose(f);
		remove(csrc);
		return -1;
	}
	fclose(f);

	snprintf(cmd, sizeof(cmd), "%s -O1 -w -shared -fPIC -o %s %s 2>/dev/null",
		 cc, b->so, csrc);
	if (system(cmd) != 0) {
		remove(csrc);
		return -1;
	}
	remove(csrc);

	b->handle = dlopen(b->so, RTLD_NOW);
	if (!b->handle)
		return -1;

	*(void **)(&b->fn) = dlsym(b->handle, "filter");
	if (!b->fn) {
		dlclose(b->handle);
		b->handle = NULL;
		return -1;
	}
	return 0;
}

static void drop(struct built *b)
{
	if (b->handle)
		dlclose(b->handle);
	remove(b->so);
	b->handle = NULL;
}

int main(void)
{
	uint8_t pkt[PKT_MAX];
	int     i, j, checked = 0, failures = 0;

	printf("== filter expressions ==\n");
	for (i = 0; i < cbpf_test_expr_count; i++) {
		struct cbpfc_expr *e;
		struct built       b = { NULL, NULL, "" };
		size_t             n;
		const struct cbpfc_insn *insns;

		e = cbpfc_expr_new(cbpf_test_exprs[i]);
		if (!e) {
			fprintf(stderr, "  SKIP \"%s\": %s\n", cbpf_test_exprs[i],
				cbpfc_errmsg());
			continue;
		}
		insns = cbpfc_expr_insns(e, &n);

		if (build(insns, n, &b) != 0) {
			fprintf(stderr, "  FAIL \"%s\": cannot build the generated C\n",
				cbpf_test_exprs[i]);
			failures++;
			cbpfc_expr_free(e);
			continue;
		}
		checked++;

		for (j = 0; j < PKT_COUNT; j++) {
			size_t   len = cbpf_test_packet(j, pkt);
			uint32_t got = b.fn(pkt, pkt + len);
			uint32_t want = cbpfc_expr_bpf_filter(e, pkt, len);

			if (got != want) {
				if (failures < 10)
					fprintf(stderr,
						"  FAIL \"%s\" pkt#%d len=%zu: generated=%u libpcap=%u\n",
						cbpf_test_exprs[i], j, len, got, want);
				failures++;
			}
		}
		drop(&b);
		cbpfc_expr_free(e);
	}

	printf("   %d expressions, %d packets each\n", checked, PKT_COUNT);
	if (failures) {
		printf("FAILED: %d mismatches\n", failures);
		return 1;
	}
	printf("OK\n");
	return 0;
}
