spdmd_headers = [
  '.',
  '..',
  '../libspdmcpp/headers_public'
]

sources = [
  'spdm_fuzzer_app.cpp',
  'spdm_fuzzer_config.cpp',
  'spdm_fuzzer_fixture.cpp',
  'spdm_fuzzer_requester.cpp',
  'spdm_fuzzer_responder.cpp',
  'spdm_fuzzer_predefined_responses.cpp'
]

executable(
	'spdm_wrapper',
	sources,
    implicit_include_directories: false,
    include_directories: include_directories(spdmd_headers),	
    link_with: libspdmcpp_requester,
	dependencies: [
		CLI11_dep, 
		crypto_deps],
	install: true
)

