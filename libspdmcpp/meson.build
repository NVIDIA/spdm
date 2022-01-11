
common_sources = [
	'common.cpp',
	'connection.cpp',
	'packet.cpp',
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
		'requester.cpp',
	],
	version : '0.0.0',
	soversion : '0',
	include_directories : incdir,
	dependencies : [ crypto_deps ],
	install : true
)
libspdmcpp_requester_dep = declare_dependency(link_with : libspdmcpp_requester, include_directories : incdir_pub)

libspdmcpp_responder = library('spdmcpp_responder',
	[
		common_sources,
		'responder.cpp',
	],
	version : '0.0.0',
	soversion : '0',
	include_directories : incdir,
	dependencies : [ crypto_deps ],
	install : true
)

if get_option('tests').enabled()
	subdir('tests')
endif
