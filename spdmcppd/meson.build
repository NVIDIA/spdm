
executable('spdmcppd',
	'main.cpp',
	dependencies: [sdbusplus, sdeventplus],
	install : true
)

if get_option('tests').enabled()
	subdir('tests')
endif
