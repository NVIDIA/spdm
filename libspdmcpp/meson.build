
common_sources = [
	'connection.cpp',
]

common_headers_public = [
	'headers_public/spdmcpp/common.hpp',
]

install_headers(
	common_headers_public,
	subdir : 'libspdmcpp'
)

incdir_pub = include_directories( 'headers_public')

incdir = include_directories( 'headers_public', 'headers')

libspdmcpp_requester = library('spdmcpp_requester',
	[
		common_sources,
	],
	version : meson.project_version(),
	soversion : meson.project_version(),
	include_directories : incdir,
	dependencies : [ crypto_deps ],
	install : true
)
libspdmcpp_requester_dep = declare_dependency(link_with : libspdmcpp_requester, include_directories : incdir_pub)

libspdmcpp_responder = library('spdmcpp_responder',
	[
		common_sources,
	],
	version : meson.project_version(),
	soversion : meson.project_version(),
	include_directories : incdir,
	dependencies : [ crypto_deps ],
	install : true
)

if get_option('tests').enabled()
	subdir('tests')
endif
