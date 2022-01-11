
executable('spdmcpp_requester_emu',
	[
		'common.cpp',
		'requester.cpp'
	],
	include_directories : incdir,
	dependencies: [libspdmcpp_requester_dep, crypto_deps, sdbusplus, sdeventplus],
	install : true
)

# if get_option('tests').enabled()
# 	subdir('tests')
# endif
