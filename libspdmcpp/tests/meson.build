tests = [
  'helpers_test',
  'hash_test',
  'packet_basic_test',
  'connection_test',
]

foreach t : tests
	test(t,
		executable('libspdmcpp_' + t.underscorify(),
			t + '.cpp',
			implicit_include_directories: false,
			include_directories : incdir,
	#		link_args: dynamic_linker,
			dependencies: [
				libspdmcpp_requester_dep,
				crypto_deps,
				gtest,
				gmock
			]
		),
		workdir: meson.current_source_dir()
	)
endforeach

