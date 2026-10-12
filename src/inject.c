/*
 * inject.c - splice a compiled filter into a pre-compiled host eBPF object
 * and hand the result to libbpf.
 *
 * This is the pwru pattern. The host program is written in C, compiled once
 * ahead of time to an ELF object and shipped - no clang is needed where it
 * runs. It contains a placeholder function:
 *
 *     __attribute__((noinline))
 *     static unsigned int filter_pcap(void *a, void *b, void *c,
 *                                     void *data, void *data_end)
 *     { return (data != data_end) && (a == b) && (b == c); }
 *
 * The five parameters fix the register contract (a/b/c land in r1-r3 and are
 * free scratch registers for the injected code, data in r4, data_end in r5).
 * The body is not a dummy: the fragment writes its result into r4 and clears
 * r1/r2/r3/r5, so the expression evaluates to "result != 0" - it converts the
 * filter result into a boolean.
 *
 * The splice is an edit of the object's ELF, done in memory:
 *
 *   1. the fragment is inserted at the start of the placeholder's body, so the
 *      section holding it is rebuilt as "everything before the body + the
 *      fragment + the body (unchanged)";
 *   2. that rebuilt section is appended at the end of the file and its section
 *      header is pointed at it.
 *
 * Nothing else has to move. In a relocatable ELF every value except sh_offset
 * and e_shoff is section-relative - st_value and r_offset are offsets within
 * their section - so growing a section only changes that section's
 * sh_offset/sh_size and the placeholder's st_size. The flip side is that the
 * placeholder must be the last thing in its section; anything after it would
 * shift, and that is rejected rather than silently corrupted.
 *
 * Everything past that is libbpf's job: it flattens the section into the
 * program, resolves the call to the placeholder, creates the maps the host
 * declares, fills in their fds and loads the program. That is why there is no
 * map code, no flattening and no relative-offset rewriting here - and why the
 * caller gets a real bpf_object that works with every libbpf API.
 */
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "cbpfc.h"

#define INSN_SZ 8

/* Where a function lives, and where its ELF records are. */
struct found {
	size_t sym_idx;      /* index in .symtab */
	size_t sec_idx;      /* section holding the function */
	size_t off;          /* byte offset within that section */
	size_t size;         /* body size in bytes */
	size_t symtab_off;   /* file offset of .symtab */
};

/* Locating */

static int find_func(Elf *e, const char *name, struct found *f)
{
	Elf_Scn   *scn, *symscn = NULL;
	GElf_Shdr  sh;
	Elf_Data  *symdata;
	int        i, n;

	for (scn = NULL; (scn = elf_nextscn(e, scn)); ) {
		GElf_Shdr s;

		if (gelf_getshdr(scn, &s) && s.sh_type == SHT_SYMTAB) {
			symscn = scn;
			sh = s;
			break;
		}
	}
	if (!symscn)
		return -1;

	symdata = elf_getdata(symscn, NULL);
	if (!symdata || sh.sh_entsize == 0)
		return -1;

	n = (int)(sh.sh_size / sh.sh_entsize);
	for (i = 0; i < n; i++) {
		GElf_Sym    sym;
		const char *nm;

		if (!gelf_getsym(symdata, i, &sym))
			continue;
		if (GELF_ST_TYPE(sym.st_info) != STT_FUNC || sym.st_shndx == SHN_UNDEF)
			continue;
		nm = elf_strptr(e, sh.sh_link, sym.st_name);
		if (!nm || strcmp(nm, name) != 0)
			continue;

		f->sym_idx    = (size_t)i;
		f->sec_idx    = sym.st_shndx;
		f->off        = (size_t)sym.st_value;
		f->size       = (size_t)sym.st_size;
		f->symtab_off = (size_t)sh.sh_offset;
		return 0;
	}
	return -1;
}

static int find_symtab(Elf *e, Elf_Scn **scn_out, GElf_Shdr *sh_out)
{
	Elf_Scn *scn = NULL;

	while ((scn = elf_nextscn(e, scn))) {
		GElf_Shdr s;

		if (gelf_getshdr(scn, &s) && s.sh_type == SHT_SYMTAB) {
			*scn_out = scn;
			*sh_out  = s;
			return 0;
		}
	}
	return -1;
}

/* The placeholder must be the last thing in its section: rebuilding the
 * section only works if nothing after it moves. */
static int check_nothing_follows(Elf *e, const struct found *f, const char *name,
				 char *err, size_t errsz)
{
	Elf_Scn   *scn, *symscn = NULL;
	GElf_Shdr  symsh;
	Elf_Data  *symdata;
	size_t     i, n;

	if (find_symtab(e, &symscn, &symsh) == 0 &&
	    (symdata = elf_getdata(symscn, NULL)) != NULL && symsh.sh_entsize) {
		n = symsh.sh_size / symsh.sh_entsize;
		for (i = 0; i < n; i++) {
			GElf_Sym sym;

			if (!gelf_getsym(symdata, (int)i, &sym))
				continue;
			if (i == f->sym_idx || sym.st_shndx != f->sec_idx)
				continue;
			if (sym.st_size == 0)
				continue;
			if (GELF_ST_TYPE(sym.st_info) != STT_FUNC &&
			    GELF_ST_TYPE(sym.st_info) != STT_OBJECT)
				continue;
			if ((size_t)sym.st_value + (size_t)sym.st_size > f->off) {
				if (err)
					snprintf(err, errsz,
						 "%s must be the last symbol in its section,"
						 " but another symbol follows it", name);
				return -1;
			}
		}
	}

	/* A relocation anywhere at or past the body would end up pointing into
	 * the fragment instead of at the instruction it patches. */
	for (scn = NULL; (scn = elf_nextscn(e, scn)); ) {
		GElf_Shdr sh;
		Elf_Data  *d;
		size_t     k, m;

		if (!gelf_getshdr(scn, &sh))
			continue;
		if (sh.sh_type != SHT_REL || sh.sh_info != f->sec_idx)
			continue;
		d = elf_getdata(scn, NULL);
		if (!d || sh.sh_entsize == 0)
			continue;

		m = sh.sh_size / sh.sh_entsize;
		for (k = 0; k < m; k++) {
			GElf_Rel rel;

			if (!gelf_getrel(d, (int)k, &rel))
				continue;
			if ((size_t)rel.r_offset >= f->off) {
				if (err)
					snprintf(err, errsz,
						 "%s has a relocation inside or after its body",
						 name);
				return -1;
			}
		}
	}
	return 0;
}

/* File helpers */

static int read_all(const char *path, uint8_t **out, size_t *size_out)
{
	size_t   cap = 1u << 16, len = 0;
	uint8_t *buf;
	int      fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	buf = malloc(cap);
	if (!buf) {
		close(fd);
		errno = ENOMEM;
		return -1;
	}

	for (;;) {
		ssize_t r;

		if (len == cap) {
			uint8_t *nb = realloc(buf, cap * 2);

			if (!nb) {
				free(buf);
				close(fd);
				errno = ENOMEM;
				return -1;
			}
			buf = nb;
			cap *= 2;
		}

		r = read(fd, buf + len, cap - len);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			close(fd);
			return -1;
		}
		if (r == 0)
			break;
		len += (size_t)r;
	}

	close(fd);
	*out      = buf;
	*size_out = len;
	return 0;
}

/* Overwrite one field of a struct in the buffer, by byte offset. Doing it this
 * way keeps the code free of casts into a byte buffer. */
static void patch(uint8_t *at, const void *value, size_t width)
{
	memcpy(at, value, width);
}

static int write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;

	while (len) {
		ssize_t w = write(fd, p, len);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p   += w;
		len -= (size_t)w;
	}
	return 0;
}

/**
 * cbpfc_inject:
 * @path: a host ELF object, compiled ahead of time
 * @func_name: the placeholder function in it, e.g. "filter_pcap"
 * @prog: the cBPF program
 * @n: number of instructions in @prog
 * @err: buffer for the error message, or NULL
 * @errsz: size of @err
 *
 * Puts @prog in front of the body of @func_name and loads the result with
 * libbpf.
 *
 * The host is written in C and compiled once; its placeholder fixes the
 * register contract through its five parameters:
 *
 *	__attribute__((noinline))
 *	static unsigned int filter_pcap(void *a, void *b, void *c,
 *					void *data, void *data_end)
 *	{ return (data != data_end) && (a == b) && (b == c); }
 *
 * a/b/c land in r1-r3 and are free scratch registers for the injected code,
 * data in r4 and data_end in r5. The body is not a dummy: the fragment writes
 * its result into r4 and clears r1/r2/r3/r5, so the expression evaluates to
 * "result != 0" - it turns the filter result into a boolean.
 *
 * The splice is an edit of the object's ELF, done in memory. libbpf then
 * flattens the section into the program, resolves the call to the placeholder,
 * creates the maps the host declares and fills in their fds. What comes back
 * is loaded, so the whole libbpf API applies to it:
 *
 *	struct bpf_program *p = bpf_object__find_program_by_name(obj, "tc_filter");
 *	int prog_fd = bpf_program__fd(p);
 *	int map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "events"));
 *	...
 *	bpf_object__close(obj);
 *
 * A failed load prints the verifier log to stderr; call libbpf_set_print()
 * first to capture it instead.
 *
 * Returns: the loaded object, or NULL with @err filled
 */
struct bpf_object *cbpfc_inject(const char *path, const char *func_name,
				const struct cbpfc_insn *prog, size_t n,
				char *err, size_t errsz)
{
	struct cbpfc_ebpf_prog frag;
	struct found   f;
	Elf           *elf = NULL;
	Elf_Scn       *scn;
	GElf_Ehdr      eh;
	GElf_Shdr      sh;
	Elf64_Shdr     newsh;
	Elf64_Sym      newsym;
	uint8_t       *buf = NULL, *newbuf = NULL;
	struct bpf_object *obj = NULL;
	char           fdpath[64];
	size_t         size = 0, plain, new_text, new_off, new_size;
	int            mfd = -1, rc = -1;

#define FAIL(...) do { if (err) snprintf(err, errsz, __VA_ARGS__); goto out; } while (0)

	memset(&frag, 0, sizeof(frag));

	if (cbpfc_to_ebpf(prog, n, &frag) != 0)
		FAIL("cannot compile the filter fragment");

	if (read_all(path, &buf, &size) != 0)
		FAIL("cannot read %s: %s", path, strerror(errno));

	if (elf_version(EV_CURRENT) == EV_NONE)
		FAIL("libelf initialisation failed");

	elf = elf_memory((char *)buf, size);
	if (!elf)
		FAIL("cannot read %s as ELF", path);

	if (!gelf_getehdr(elf, &eh))
		FAIL("cannot read the ELF header of %s", path);
	if (eh.e_ident[EI_CLASS] != ELFCLASS64 ||
	    eh.e_ident[EI_DATA] != ELFDATA2LSB ||
	    eh.e_shentsize != sizeof(Elf64_Shdr))
		FAIL("%s is not a 64-bit little-endian ELF object", path);

	if (find_func(elf, func_name, &f) != 0)
		FAIL("no function named \"%s\" in %s", func_name, path);
	if (f.size == 0)
		FAIL("\"%s\" has an empty body", func_name);

	if (check_nothing_follows(elf, &f, func_name, err, errsz) != 0)
		goto out;

	scn = elf_getscn(elf, f.sec_idx);
	if (!scn || !gelf_getshdr(scn, &sh))
		FAIL("cannot read the section holding \"%s\"", func_name);
	if (f.off + f.size > sh.sh_size)
		FAIL("\"%s\" extends past the end of its section", func_name);

	/* The fragment replaces the *beginning* of the placeholder's body, not the
	 * whole function: it hands its result to the original body, which is what
	 * converts it into a boolean and returns. So the section grows by the size
	 * of the fragment and the function's size grows with it. The rebuilt
	 * section is appended at the end of the file so that no other section's
	 * sh_offset moves. */
	plain    = frag.n * INSN_SZ;
	new_text = sh.sh_size + plain;
	new_off  = (size + 7u) & ~(size_t)7;
	new_size = new_off + new_text;

	newbuf = calloc(1, new_size);
	if (!newbuf)
		FAIL("out of memory");
	memcpy(newbuf, buf, size);

	memcpy(newbuf + new_off, buf + sh.sh_offset, f.off);
	memcpy(newbuf + new_off + f.off, frag.insn, plain);
	memcpy(newbuf + new_off + f.off + plain,
	       buf + sh.sh_offset + f.off, sh.sh_size - f.off);

	/* Point the section header at the new copy, and record the new length of
	 * the placeholder's body. Both records live in the part of the file that
	 * was copied verbatim, so they are already in newbuf. */
	memcpy(&newsh, newbuf + eh.e_shoff + f.sec_idx * eh.e_shentsize, sizeof(newsh));
	newsh.sh_offset = new_off;
	newsh.sh_size   = new_text;
	patch(newbuf + eh.e_shoff + f.sec_idx * eh.e_shentsize, &newsh, sizeof(newsh));

	memcpy(&newsym, newbuf + f.symtab_off + f.sym_idx * sizeof(newsym), sizeof(newsym));
	newsym.st_size = plain + f.size;
	patch(newbuf + f.symtab_off + f.sym_idx * sizeof(newsym), &newsym, sizeof(newsym));

	elf_end(elf);
	elf = NULL;

	/* Hand the patched object to libbpf as an anonymous in-memory file. It
	 * opens and maps the file itself, so the bytes stay alive for as long as
	 * the bpf_object without us having to hold on to the buffer. */
	mfd = memfd_create("cbpfc", MFD_CLOEXEC);
	if (mfd < 0)
		FAIL("cannot create an in-memory object: %s", strerror(errno));
	if (write_all(mfd, newbuf, new_size) != 0)
		FAIL("cannot write the patched object: %s", strerror(errno));
	snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", mfd);

	obj = bpf_object__open_file(fdpath, NULL);
	if (!obj)
		FAIL("libbpf cannot open the patched object: %s", strerror(errno));

	/* libbpf flattens the section into the program, resolves the call to the
	 * placeholder, creates the host's maps and fills in their fds. It prints
	 * the verifier log to stderr on failure - call libbpf_set_print() to
	 * capture it instead. */
	if (bpf_object__load(obj) != 0)
		FAIL("libbpf cannot load the patched object: %s", strerror(errno));

	rc = 0;

out:
	free(buf);
	free(newbuf);
	if (mfd >= 0)
		close(mfd);
	if (elf)
		elf_end(elf);
	cbpfc_ebpf_prog_free(&frag);
	if (rc != 0 && obj) {
		bpf_object__close(obj);
		obj = NULL;
	}
	return obj;
#undef FAIL
}
