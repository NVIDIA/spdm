spdmcppd_headers = [
  '.',
  '..',
  '../libspdmcpp/headers_public'
]

sources = [
	'spdmd.cpp',
	'instance_id.cpp',
	'dbus_impl_responder.cpp',
	'utils.cpp',
]

executable(
	'spdmd',
	sources,
    implicit_include_directories: false,
    include_directories: include_directories(spdmcppd_headers),	
	dependencies: [
		CLI11_dep,
		nlohmann_json,
		phosphor_dbus_interfaces,
		sdbusplus, 
		sdeventplus],
	install: true
)

if get_option('spdmd').enabled()
  systemd_system_unit_dir = dependency('systemd').get_variable(
          pkgconfig: 'systemdsystemunitdir')

  configure_file(
    copy: true,
    input: 'service_files/spdmd.service',
    install: true,
    install_dir: systemd_system_unit_dir,
    output: 'spdmd.service',
  )
endif

if get_option('tests').enabled()
	subdir('tests')
endif
