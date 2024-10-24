#project('mctp packet corrupt library', 'c')

source_files = [
  'syscalls_wrap.c',
  'pktcorrupt.c',
  'random.c',
  'pktmod.c',
  'response_if_ready.c',
  'userio.c',
]
version_file = 'version.txt'
library_name = 'mctpacketcorrupt'
version_script_output = 'version_script.tmp'

# Generate the version script file
gen_version_script = custom_target('gen_version_script',
      input: version_file,
      output: version_script_output,
      command: ['cp', '@INPUT@', '@OUTPUT@']
)

# Create the library target
libpacket_corrupt = shared_library(library_name,
	sources: source_files,
	link_depends: gen_version_script,
	link_args: ['-Wl,--version-script=' + join_paths(meson.current_build_dir(), version_script_output)]
)


