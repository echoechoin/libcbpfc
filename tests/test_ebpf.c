/*
 * test_ebpf.c - run the generated filter in the kernel and compare with libpcap.
 *
 * There is one code path: the filter is compiled to an eBPF fragment, spliced
 * into a pre-compiled host object (skeleton.o, which contains the filter_pcap
 * placeholder) and loaded with libbpf. Every packet is then pushed through the
 * loaded program with BPF_PROG_TEST_RUN and the verdict compared against
 * libpcap's bpf_filter() - the reference interpreter.
 *
 * Two passes:
 *
 *   1. Real filter expressions, compiled by libpcap to cBPF.
 *   2. Randomly generated cBPF programs, which reach instruction
 *      combinations no real expression produces.
 *
 * The host maps a match to TC_ACT_OK (0) and a non-match to TC_ACT_SHOT (2),
 * so the expected verdict is derived from the cBPF return value.
 *
 * The host keeps helper functions in .text on both sides of the placeholder,
 * which is what makes the run cover the records cbpfc_inject() has to move when
 * the placeholder grows. check_layout() asserts that up front: a compiler
 * change that laid them out differently would leave the test passing while
 * quietly covering less.
 *
 * Needs root: loading a BPF program requires CAP_BPF. The path to skeleton.o
 * is passed as the first argument. Without root the test exits 77, which meson
 * reports as skipped.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>       /* bpf_test_run_opts */
#include <bpf/libbpf.h>
#include <gelf.h>
#include <libelf.h>

#include "cbpfc.h"
#include "common.h"

#define RANDOM_PROGRAMS 400

static int failures;

static void report(const char *label, int index, size_t len,
		   uint32_t got, uint32_t want)
{
	if (failures < 10)
		fprintf(stderr, "  FAIL %s #%d len=%zu: kernel=%u libpcap=%u\n",
			label, index, len, got, want);
	failures++;
}

/* Push one packet through a loaded program via BPF_PROG_TEST_RUN. */
static int test_run(int fd, const void *data, uint32_t len, uint32_t *retval)
{
	static uint8_t out[4096];
	struct bpf_test_run_opts o = {
		.sz            = sizeof(o),
		.data_in       = data,
		.data_size_in  = len,
		.data_out      = out,
		.data_size_out = sizeof(out),
		.repeat        = 1,
	};

	if (bpf_prog_test_run_opts(fd, &o) != 0)
		return -1;
	*retval = o.retval;
	return 0;
}

/* Replace filter_pcap, load, and compare the result over the whole corpus.
 * Returns 0 if it was checked, -1 if it could not be built or loaded. */
static int run_one(const char *path, const struct cbpfc_insn *prog, size_t n,
		   const char *label, int n_pkts)
{
	struct bpf_object  *obj;
	struct bpf_program *p;
	uint8_t     pkt[PKT_MAX];
	int         fd, bad = 0, i;

	obj = cbpfc_inject(path, "filter_pcap", prog, n);
	if (!obj) {
		fprintf(stderr, "  FAIL %s: %s\n", label, cbpfc_errmsg());
		failures++;
		return -1;
	}

	p = bpf_object__find_program_by_name(obj, "tc_filter");
	if (!p) {
		fprintf(stderr, "  FAIL %s: no program named tc_filter\n", label);
		failures++;
		bpf_object__close(obj);
		return -1;
	}
	fd = bpf_program__fd(p);      /* owned by the object, don't close it */

	for (i = 0; i < n_pkts; i++) {
		size_t   len = cbpf_test_packet(i, pkt);
		uint32_t got = 0, want;

		/* TC classifies real frames; shorter packets cannot occur. */
		if (len < 14)
			continue;
		if (test_run(fd, pkt, (uint32_t)len, &got) != 0)
			continue;

		/* The host turns a match into TC_ACT_OK (0), a non-match into
		 * TC_ACT_SHOT (2). */
		want = cbpf_libpcap_filter(prog, pkt, len) ? 0u : 2u;
		if (got != want) {
			report(label, i, len, got, want);
			bad++;
		}
	}

	bpf_object__close(obj);
	return bad;
}

/* The placeholder has to sit in .text with a function on each side of it:
 * before_helper is the code that must not move, after_helper the code that
 * must. Returns 0 if the layout is right, -1 with a message otherwise. */
static int check_layout(const char *path)
{
	Elf        *elf;
	Elf_Scn    *scn = NULL, *symscn = NULL;
	GElf_Ehdr   eh;
	GElf_Shdr   symsh, secsh;
	Elf_Data   *symdata;
	const char *secname = "?";
	size_t      sec_idx = 0, off = 0, size = 0, n = 0, i;
	int         before = 0, after = 0, fd, ok = -1;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	elf_version(EV_CURRENT);
	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		close(fd);
		return -1;
	}

	if (!gelf_getehdr(elf, &eh))
		goto out;
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr s;

		if (gelf_getshdr(scn, &s) && s.sh_type == SHT_SYMTAB) {
			symscn = scn;
			symsh  = s;
			break;
		}
	}
	if (!symscn || !(symdata = elf_getdata(symscn, NULL)) || !symsh.sh_entsize)
		goto out;

	n = symsh.sh_size / symsh.sh_entsize;
	for (i = 0; i < n; i++) {
		GElf_Sym    sym;
		const char *nm;

		if (!gelf_getsym(symdata, (int)i, &sym))
			continue;
		nm = elf_strptr(elf, symsh.sh_link, sym.st_name);
		if (nm && strcmp(nm, "filter_pcap") == 0) {
			sec_idx = sym.st_shndx;
			off     = (size_t)sym.st_value;
			size    = (size_t)sym.st_size;
			break;
		}
	}
	scn = elf_getscn(elf, sec_idx);
	if (sec_idx && scn && gelf_getshdr(scn, &secsh)) {
		const char *nm = elf_strptr(elf, eh.e_shstrndx, secsh.sh_name);

		if (nm)
			secname = nm;
	}

	for (i = 0; i < n; i++) {
		GElf_Sym sym;

		if (!gelf_getsym(symdata, (int)i, &sym))
			continue;
		if (sym.st_shndx != sec_idx || sym.st_size == 0 ||
		    GELF_ST_TYPE(sym.st_info) != STT_FUNC)
			continue;
		if ((size_t)sym.st_value + sym.st_size <= off)
			before++;
		else if ((size_t)sym.st_value >= off + size)
			after++;
	}

	if (size && strcmp(secname, ".text") == 0 && before > 0 && after > 0)
		ok = 0;
	else
		fprintf(stderr,
			"test_ebpf: %s no longer has the layout this test needs:\n"
			"  filter_pcap in %s at offset %zu size %zu"
			" (%d functions before, %d after)\n"
			"  expected it in .text with one on each side\n",
			path, secname, off, size, before, after);
out:
	elf_end(elf);
	close(fd);
	return ok;
}

/* Random cBPF programs */

static uint64_t rnd_state;

static unsigned rnd(void)
{
	return cbpf_rand(&rnd_state);
}

/* Most packet offsets stay small so that the programs keep matching something,
 * but a quarter of them come from the edges: where the verifier's 16-bit offset
 * limit bites (32767/32768) and where a cBPF offset stops being usable at all
 * (65535). */
static uint32_t rnd_offset(void)
{
	static const uint32_t edge[] = {
		0, 1, 2, 13, 14, 40, 32766, 32767, 32768, 65534, 65535,
	};

	if (rnd() % 4)
		return rnd() % 64;
	return edge[rnd() % (sizeof(edge) / sizeof(edge[0]))];
}

/* Build a random but well-formed cBPF program.
 *
 * The first 32 slots store distinct values into M[0..15]: libpcap's
 * bpf_filter() does not initialise its scratch memory, so reading an unwritten
 * slot returns stack garbage. Real filters always write before reading, and
 * pre-filling keeps the comparison meaningful.
 */
#define PRO   32
#define RN    14
#define RLEN  (PRO + RN + 1)

static void random_program(struct cbpfc_insn *prog)
{
	static const uint16_t ops[] = {
		0x00, 0x01, 0x20, 0x28, 0x30, 0x40, 0x48, 0x50, 0x80, 0x81,
		0x60, 0x61, 0x02, 0x03, 0xb1,
		0x04, 0x0c, 0x14, 0x1c, 0x24, 0x2c, 0x34, 0x3c, 0x44, 0x4c,
		0x54, 0x5c, 0x64, 0x6c, 0x74, 0x7c, 0x84, 0x94, 0x9c, 0xa4,
		0xac, 0x07, 0x87,
	};
	static const uint16_t jmps[] = { 0x05, 0x15, 0x1d, 0x25, 0x2d,
					 0x35, 0x3d, 0x45, 0x4d };
	int i, k;

	for (k = 0; k < 16; k++) {
		prog[2 * k].code = 0x00;                /* ld  #value */
		prog[2 * k].jt = prog[2 * k].jf = 0;
		prog[2 * k].k = (uint32_t)(k * 7 + 1);
		prog[2 * k + 1].code = 0x02;            /* st  M[k]   */
		prog[2 * k + 1].jt = prog[2 * k + 1].jf = 0;
		prog[2 * k + 1].k = (uint32_t)k;
	}

	for (i = PRO; i < RLEN - 1; i++) {
		uint8_t span = (uint8_t)(RLEN - i - 1);

		prog[i].jt = prog[i].jf = 0;

		if (rnd() % 5 == 0) {
			prog[i].code = jmps[rnd() % (sizeof(jmps) / sizeof(jmps[0]))];
			prog[i].jt = (uint8_t)(rnd() % span);
			prog[i].jf = (uint8_t)(rnd() % span);
			prog[i].k = (prog[i].code == 0x05) ? rnd() % span : rnd();
			continue;
		}

		prog[i].code = ops[rnd() % (sizeof(ops) / sizeof(ops[0]))];
		switch (prog[i].code & 0x07) {
		case 0x02: case 0x03:                   /* st / stx */
			prog[i].k = rnd() % 16;
			break;
		case 0x00: case 0x01:                   /* ld / ldx */
			if ((prog[i].code & 0x60) == 0x60)      prog[i].k = rnd() % 16;
			else if ((prog[i].code & 0xe0) == 0xa0) prog[i].k = rnd_offset();
			else if ((prog[i].code & 0xe0) == 0x80) prog[i].k = 0;
			else                                    prog[i].k = rnd_offset();
			break;
		case 0x04:                              /* alu */
			if (prog[i].code == 0x84)                               prog[i].k = 0;
			else if ((prog[i].code & 0xf0) == 0x60 ||
				 (prog[i].code & 0xf0) == 0x70)                 prog[i].k = rnd() % 32;
			else                                                    prog[i].k = rnd() % 1000 + 1;
			break;
		default:
			prog[i].k = rnd();
			break;
		}
	}

	prog[RLEN - 1].code = 0x06;                     /* ret #k */
	prog[RLEN - 1].jt = prog[RLEN - 1].jf = 0;
	prog[RLEN - 1].k = (rnd() % 3) ? 1 : 0;
}

int main(int argc, char **argv)
{
	struct cbpfc_insn prog[RLEN];
	const char *path;
	int i, checked = 0, loaded = 0;

	if (geteuid() != 0) {
		fprintf(stderr, "test_ebpf: needs root, skipping\n");
		return 77;
	}
	if (argc < 2) {
		fprintf(stderr, "usage: test_ebpf <skeleton.o>\n");
		return 2;
	}
	path = argv[1];

	if (check_layout(path) != 0)
		return 1;

	printf("== filter expressions ==\n");
	for (i = 0; i < cbpf_test_expr_count; i++) {
		struct cbpfc_expr *e;
		size_t             n;
		const struct cbpfc_insn *insns;

		e = cbpfc_expr_new(cbpf_test_exprs[i]);
		if (!e) {
			fprintf(stderr, "  SKIP \"%s\": %s\n", cbpf_test_exprs[i],
				cbpfc_errmsg());
			continue;
		}
		insns = cbpfc_expr_insns(e, &n);
		if (run_one(path, insns, n, cbpf_test_exprs[i], PKT_COUNT) >= 0)
			checked++;
		cbpfc_expr_free(e);
	}
	printf("   %d expressions, %d packets each\n", checked, PKT_COUNT);

	printf("== random cBPF programs ==\n");
	rnd_state = 0x9e3779b97f4a7c15ULL;
	for (i = 0; i < RANDOM_PROGRAMS; i++) {
		char label[32];

		random_program(prog);
		snprintf(label, sizeof(label), "random#%d", i);
		if (run_one(path, prog, RLEN, label, PKT_COUNT < 8 ? PKT_COUNT : 8) >= 0)
			loaded++;
	}
	printf("   %d/%d programs loaded and checked\n", loaded, RANDOM_PROGRAMS);

	if (failures) {
		printf("FAILED: %d mismatches\n", failures);
		return 1;
	}
	printf("OK\n");
	return 0;
}
