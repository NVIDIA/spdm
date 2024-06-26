project('spdmcpp',
	'cpp', 'c',
	version: '0.1.0',
	meson_version: '>=0.58.0',
	default_options: ['cpp_std=c++20', 'warning_level=3']
)

if get_option('tests').enabled()
	gtest = dependency('gtest', main: true, disabler: true, required: false)
	gmock = dependency('gmock', disabler: true, required: false)
endif

#at the moment we can't use default_option werror=true because it's passed to subprojects and subproject dependencies, and atm specifically fmt fails
add_project_arguments([ '-Werror', '-fno-sanitize=alignment'], language: ['c', 'cpp'])

# Wno-psabi reduces the number of "Note:" messages when cross-compiling some STL
# stuff for ARM. See https://stackoverflow.com/questions/48149323/strange-gcc-warning-when-compiling-qt-project
# Basically, gcc 6 and gcc 7 are not ABI compatible, but since the whole OpenBMC
# project uses the same compiler, we can safely ignore these info notes.
add_project_arguments('-Wno-psabi', language: 'cpp')

conf_data = configuration_data()
conf_data.set_quoted('SPDMD_VERSION', meson.project_version())
conf_data.set_quoted('SPDM_WRAPPER_VERSION', meson.project_version())
conf_data.set('FETCH_SERIALNUMBER_FROM_RESPONDER', get_option('fetch_serialnumber_from_responder'))
conf_data.set('DISCOVERY_ONLY_FROM_MCTP_CONTROL', get_option('discovery_only_from_mctp_control').enabled())
conf_data.set('SPDM_JSON_CONF_FILE_NAME', get_option('conf_file_name'))
conf_data.set('USE_DEFAULT_DBUS', get_option('use_default_dbus').enabled())

conf_h_dep = declare_dependency(
    include_directories: include_directories('.'),
    sources: configure_file(
      input: 'config.h.in',
      output: 'config.h',
      configuration: conf_data
    )
)

comp = meson.get_compiler('cpp')

crypto_deps = declare_dependency(
	dependencies: [
		comp.find_library('mbedcrypto'),
		comp.find_library('mbedx509')
	]
)

sdbusplus = dependency(
  'sdbusplus',
  fallback: ['sdbusplus', 'sdbusplus_dep'],
)
phosphor_dbus_interfaces = dependency(
  'phosphor-dbus-interfaces',
  fallback: ['phosphor-dbus-interfaces', 'phosphor_dbus_interfaces_dep'],
)

sdeventplus = dependency(
  'sdeventplus',
  fallback: ['sdeventplus', 'sdeventplus_dep'],
)


if comp.has_header('CLI/CLI.hpp')
  CLI11_dep = declare_dependency()
else
  CLI11_dep = dependency(
    'CLI11',
    fallback: [ 'CLI11', 'CLI11_dep' ],
  )
endif

if comp.has_header('nlohmann/json.hpp')
    nlohmann_json = declare_dependency()
else
    nlohmann_json_proj = subproject('nlohmann', required: true)
    nlohmann_json = nlohmann_json_proj.get_variable('nlohmann_json_dep')
    nlohmann_json = nlohmann_json.as_system('system')
endif

subdir('libspdmcpp')
subdir('tools/libmctppacketcorrupt')

subdir('fuzzer')
subdir('spdmd')
subdir('spdmutil')
