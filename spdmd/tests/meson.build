tests = [
  'basic_test',
]

# if get_option('oem-ibm').enabled()
#   tests += [
#     'some_test',
#   ]
# endif

foreach t : tests
	test(t,
		executable('spdmd_' + t.underscorify(),
			t + '.cpp',
			implicit_include_directories: false,
	#		link_args: dynamic_linker,
	#			build_rpath: get_option('oe-sdk').enabled() ? rpath : '',
			dependencies: [
				gtest,
				gmock
			]
		),
		workdir: meson.current_source_dir()
	)
endforeach

