# examples/xdpdump/meson.build - a packet capture tool built on the library.
#
# The XDP host program is compiled here, at build time; only the resulting .o
# is needed at run time.

clang = find_program('clang', required : false)
if not clang.found()
  warning('clang not found: the xdpdump example is skipped')
  subdir_done()
endif

# `clang -target bpf` does not carry the architecture include directory, so
# <asm/types.h> is not found unless it is added explicitly.
triplet = run_command(cc, '-dumpmachine', check : true).stdout().strip()

# The XDP host program: compiled once here, injected into at run time.
xdpdump_bpf_o = custom_target('xdpdump.bpf.o',
  input  : 'xdpdump.bpf.c',
  output : 'xdpdump.bpf.o',
  command : [
    clang, '-O2', '-g', '-target', 'bpf',
    '-idirafter', '/usr/include/' + triplet,
    '-I' + meson.current_source_dir(),
    '-c', '@INPUT@', '-o', '@OUTPUT@',
  ],
  build_by_default : true,
)

xdpdump = executable('xdpdump', ['xdpdump.c', 'pcap_writer.c'],
  include_directories : include_directories('.'),
  dependencies : [cbpfc_dep, libpcap, libbpf],
  c_args : '-DXDPDUMP_DEFAULT_OBJ="' + meson.current_build_dir() / 'xdpdump.bpf.o' + '"',
  build_by_default : true,
)
