# xdpdump

An XDP capture tool driven by a tcpdump-style filter. It compiles the
expression, has libcbpfc splice the filter into the pre-compiled host program,
attaches the result to an interface, and writes matching packets to a pcap file
until it has the requested number:

```sh
sudo ./build/examples/xdpdump/xdpdump -i eth0 -n 100 'udp and port 53' -w dns.pcap
```

```
-i, --iface <iface>    interface to capture on (required)
-n, --count <n>        stop after capturing n packets (required)
-w, --write <file>     output pcap file (default: xdpdump.pcap)
-o, --object <file>    compiled XDP host object
-D, --drv              native XDP instead of generic
-p, --no-promisc       do not put the interface into promiscuous mode
-t, --timeout <sec>    give up after this long
-v, --verbose          print one line per captured packet
```

Like tcpdump, it puts the interface into promiscuous mode so that it also sees
frames addressed elsewhere - with `-p` to leave it alone. Both that and the
attach are things the kernel takes back on its own: promiscuous mode through an
AF_PACKET socket whose membership it refcounts, the program through a
`bpf_link` held by an fd the tool owns. So whether the tool exits, is
interrupted or is killed, the interface is left as it was.

| file | |
|---|---|
| `xdpdump.bpf.c` | the host: the XDP program, the `filter_pcap` placeholder and the ring buffer |
| `xdpdump.c` | the tool: expression to cBPF, inject, attach, drain the ring buffer |
| `xdpdump_event.h` | the ring buffer record, shared by the two sides |
| `pcap_writer.c`, `.h` | writing the capture out, kept separate so that `<pcap.h>` never meets `<linux/bpf.h>` |

`xdpdump.bpf.c` is compiled once at build time into `xdpdump.bpf.o`; only that
object is needed at run time. Nothing is ever dropped - the program returns
`XDP_PASS` for every packet, so the interface keeps working normally.

One thing in it is worth knowing about:

- **Packet copies.** The snapshot is taken in fixed-size chunks rather than with
  `bpf_xdp_load_bytes()`. That helper's length argument is `ARG_CONST_SIZE`, so
  the verifier must be able to prove it is non-zero and fits the destination -
  and clang folds away every guard that would tell it so, because it knows the
  length is just `data_end - data`. Constant-size copies compile into ordinary
  packet bound checks, which the verifier always accepts. `caplen` therefore
  ends up as the packet length rounded down to a multiple of 16.
