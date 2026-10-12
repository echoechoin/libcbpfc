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
sections and symbols in it), `clang` (only to build host objects), a kernel
with `BPF_JMP32` (5.1+).

## Example: xdpdump

`examples/xdpdump/` builds a small XDP capture tool. It takes a tcpdump-style filter,
attaches the patched program to an interface and writes matching packets to a
pcap file until it has the requested number:

```sh
sudo ./build/examples/xdpdump/xdpdump -i eth0 -n 100 'udp and port 53' -w dns.pcap
```

```
-i, --iface <iface>    interface to capture on (required)
-n, --count <n>        stop after capturing n packets (required)
-w, --write <file>     output pcap file (default: xdpdump.pcap)
-o, --object <file>    compiled XDP host object
-D, --drv              native XDP instead of generic
-t, --timeout <sec>    give up after this long
-v, --verbose          print one line per captured packet
```

`examples/xdpdump/xdpdump.bpf.c` is the host: an XDP program with the `filter_pcap`
placeholder and a ring buffer for the captured packets. It is compiled once at
build time into `xdpdump.bpf.o`; only that object is needed at run time.
Nothing is ever dropped - the program returns `XDP_PASS` for every packet, so
the interface keeps working normally.

One thing in it is worth knowing about:

- **Packet copies.** The snapshot is taken in fixed-size chunks rather than with
  `bpf_xdp_load_bytes()`. That helper's length argument is `ARG_CONST_SIZE`, so
  the verifier must be able to prove it is non-zero and fits the destination -
  and clang folds away every guard that would tell it so, because it knows the
  length is just `data_end - data`. Constant-size copies compile into ordinary
  packet bound checks, which the verifier always accepts. `caplen` therefore
  ends up as the packet length rounded down to a multiple of 16.

## Usage

Putting a filter into a program is three steps: compile the expression, inject
it into the host object, use the result.

```c
#include <cbpfc.h>

/* 1. the filter expression -> cBPF, compiled by libpcap */
char err[256];
struct cbpfc_expr *e = cbpfc_expr_new("udp and port 53", err, sizeof err);
if (!e) {
	fprintf(stderr, "bad filter: %s\n", err);
	return 1;
}
size_t n;
const struct cbpfc_insn *insns = cbpfc_expr_insns(e, &n);

/* 2. replace the placeholder in the host object and load it */
struct bpf_object *obj = cbpfc_inject("xdpdump.bpf.o", "filter_pcap",
                                      insns, n, err, sizeof err);
if (!obj) {
	fprintf(stderr, "cannot inject: %s\n", err);
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

## Limitations

- The library emits a fragment; the program type is whatever the host object's
  section says (`tc`, `xdp`, ...). Nothing is generated for a bare hook with no
  host program.
- `ld len` maps to `data_end - data` (the captured length), not libpcap's wire
  length. The two differ only for truncated captures.
- The placeholder must live in `.text`; that is the only section libbpf treats
  as a home for subprograms, and a function anywhere else is rejected as a
  static program.
