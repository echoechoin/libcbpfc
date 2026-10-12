project('libcbpfc', 'c',
  version : '0.1.0',
  license : 'BSD-2-Clause',
  default_options : [
    'c_std=c11',
    'warning_level=3',
    'buildtype=debugoptimized',
  ])

cc = meson.get_compiler('c')

# libpcap compiles filter expressions to cBPF and provides the reference
# interpreter (bpf_filter()) the tests compare against.
libpcap = dependency('libpcap')

# libbpf provides the BTF API used to read the host object's map definitions.
libbpf = dependency('libbpf')

# libelf is used to read the host object when injecting.
libelf = dependency('libelf')

add_project_arguments('-D_GNU_SOURCE', language : 'c')

inc = include_directories('include')

cbpfc_sources = files(
  'src/expr.c',
  'src/to_c.c',
  'src/to_ebpf.c',
  'src/inject.c',
)

cbpfc_deps = [libpcap, libbpf, libelf]

cbpfc = library('cbpfc',
  cbpfc_sources,
  include_directories : inc,
  dependencies : cbpfc_deps,
  install : true,
  version : meson.project_version(),
)

cbpfc_dep = declare_dependency(
  link_with : cbpfc,
  include_directories : inc,
)

install_headers('include/cbpfc.h')

subdir('tests')
subdir('examples')

summary({
  'libpcap' : libpcap.found(),
  'libbpf'  : libbpf.found(),
  'libelf'  : libelf.found(),
}, section : 'dependencies')
