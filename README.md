# libcbpfc

A classic BPF (cBPF) to eBPF compiler, in C.

It turns a tcpdump-style filter expression into:

| | |
|---|---|
| **C source** | `cbpfc_to_c()` - a plain `uint32_t filter(data, data_end)` function |
| **eBPF instructions** | `cbpfc_to_ebpf()` - a fragment for a host program to splice in |
| **A loaded `bpf_object`** | `cbpfc_inject()` - the filter spliced into a pre-compiled host program, loaded by libbpf |

## Building

```sh
meson setup build
ninja -C build
meson test -C build          # test_ebpf needs root and is skipped without it
sudo meson test -C build     # or run it directly:
sudo ./build/tests/test_ebpf ./build/tests/skeleton.o
```

Dependencies: `libpcap` (compiles expressions and provides the reference
interpreter), `libbpf` (loads the patched host object), `libelf` (locates
sections and symbols in it), `clang` (only to build host objects), and a kernel
with BPF-to-BPF calls (4.16+) - the injected filter is a function of the host
program.

## Usage

Putting a filter into a program is three steps: compile the expression, inject
it into the host object, use the result.

```c
#include <cbpfc.h>

/* 1. the filter expression -> cBPF, compiled by libpcap */
struct cbpfc_expr *e = cbpfc_expr_new("udp and port 53");
if (!e) {
	fprintf(stderr, "bad filter: %s\n", cbpfc_errmsg());
	return 1;
}
size_t n;
const struct cbpfc_insn *insns = cbpfc_expr_insns(e, &n);

/* 2. replace the placeholder in the host object and load it */
struct bpf_object *obj = cbpfc_inject("xdpdump.bpf.o", "filter_pcap", insns, n);
if (!obj) {
	fprintf(stderr, "cannot inject: %s\n", cbpfc_errmsg());
	return 1;
}

/* 3. what comes back is an ordinary libbpf object */
struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_dump");
int prog_fd = bpf_program__fd(prog);
int events  = bpf_map__fd(bpf_object__find_map_by_name(obj, "events"));

bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);

        ...

bpf_object__close(obj);      /* closes the program and its maps too */
cbpfc_expr_free(e);
```

The host object is C, compiled once ahead of time - only the `.o` is needed
where the filter runs. It has to contain a placeholder function, and its five
parameters are the register contract:

```c
__attribute__((noinline))
static unsigned int filter_pcap(void *_a, void *__b, void *__c,
                                void *data, void *data_end)
{
	return (data != data_end) && (_a == __b) && (__b == __c);
}
```

a/b/c land in r1-r3 and are scratch registers for the injected code, data in r4
and data_end in r5. The body is not a dummy: the compiled filter writes its
result into r4 and zeroes r1/r2/r3/r5, so the expression evaluates to
"result != 0" - that is where the filter result becomes the host's verdict.

`cbpfc_inject()` puts the filter in front of that body by editing the object's
ELF in memory, then hands the object to libbpf, which flattens it, resolves the
call to the placeholder, creates the maps the host declares and fills in their
fds.

The splice is cheap because a relocatable ELF stores everything except
`sh_offset` and `e_shoff` as section-relative offsets (`st_value`, `r_offset`).
Growing the section that holds the placeholder therefore only means updating
that section's `sh_offset`/`sh_size` and the placeholder's `st_size` - and the
rebuilt section is appended at the end of the file, so nothing else moves.
