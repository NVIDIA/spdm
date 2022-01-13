spdmcppd_headers = [
  '.',
  '../libspdmcpp/headers_public'
]

sources = [
	'spdmd.cpp',
]

executable(
	'spdmd',
	sources,
    implicit_include_directories: false,
    include_directories: include_directories(spdmcppd_headers),	
	dependencies: [
		CLI11_dep,
		phosphor_dbus_interfaces,
		sdbusplus, 
		sdeventplus],
	install: true
)

if get_option('tests').enabled()
	subdir('tests')
endif
