# tests/meson.build

test_common = static_library('cbpfc_test_common', 'common.c',
  include_directories : [include_directories('.'), inc],
  # common.c holds the libpcap reference interpreter, so that files which talk
  # to libbpf do not have to include <pcap.h> as well.
  dependencies : libpcap,
)

dl = cc.find_library('dl', required : false)

# The host object is compiled once, at build time. Only the resulting .o is
# needed at run time - that is the whole point of the injection test.
skeleton_o = []
clang = find_program('clang', required : false)
have_skeleton = clang.found()
if have_skeleton
  # `clang -target bpf` does not carry the architecture include directory, so
  # <asm/types.h> is not found unless it is added explicitly.
  triplet = run_command(cc, '-dumpmachine', check : true).stdout().strip()

  skeleton_o = custom_target('skeleton.o',
    input  : 'skeleton.c',
    output : 'skeleton.o',
    command : [
      clang, '-O2', '-g', '-target', 'bpf',
      '-idirafter', '/usr/include/' + triplet,
      '-c', '@INPUT@', '-o', '@OUTPUT@',
    ],
    build_by_default : true,
  )
  message('building skeleton.o with ' + clang.full_path())
else
  warning('clang not found: the injection test will be skipped')
endif

test_sources = {
  'to_c' : 'test_to_c.c',
  'ebpf' : 'test_ebpf.c',
}

foreach name, src : test_sources
  args = []
  deps = [libpcap]

  if name == 'to_c'
    deps += dl
  else
    if not have_skeleton
      continue
    endif
    args += skeleton_o
    deps += [libbpf, libelf]   # libelf: check_layout() reads the host object
  endif

  exe = executable('test_' + name, src,
    link_with : test_common,
    include_directories : include_directories('.'),
    dependencies : [cbpfc_dep] + deps,
  )

  # test_ebpf needs root; without it it exits 77 and meson reports it as
  # skipped. Run it directly with sudo for a real check.
  test(name, exe, args : args, timeout : 300)
endforeach
