spdmd_headers = [
  '.',
  '..',
  '../libspdmcpp/headers_public'
]

sources = [
  'spdmtool_app.cpp',
  'spdm_tool.cpp',
  'str_conv.cpp',
  'enumerate_endpoints.cpp'
]

executable(
	'spdmtool',
	sources,
    implicit_include_directories: false,
    include_directories: include_directories(spdmd_headers),
    link_with: libspdmcpp_requester,
	dependencies: [
		CLI11_dep,
		crypto_deps,
    nlohmann_json,
    sdbusplus
    ],
	install: true
)

