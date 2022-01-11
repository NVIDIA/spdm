tests = [
  'basic_test',
  'packet_basic_test',
]

foreach t : tests
	test(t,
		executable('libspdmcpp_' + t.underscorify(),
			t + '.cpp',
			implicit_include_directories: false,
			include_directories : incdir,
	#		link_args: dynamic_linker,
			dependencies: [
				gtest,
				gmock
			]
		),
		workdir: meson.current_source_dir()
	)
endforeach

