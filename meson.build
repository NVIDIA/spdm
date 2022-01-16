project('spdmcpp',
	'cpp',
	version: '0.1.0',
	meson_version: '>=0.56.2',
	default_options: ['cpp_std=c++20', 'warning_level=3', 'werror=true']
)

if get_option('tests').enabled()
	gtest = dependency('gtest', main: true, disabler: true, required: false)
	gmock = dependency('gmock', disabler: true, required: false)
	assert(gtest.found(), 'Couldn\'t find gtest, either provide or disable tests with: -Dtests=disabled')
	assert(gmock.found(), 'Couldn\'t find gmock, either provide or disable tests with: -Dtests=disabled')
endif

# Wno-psabi reduces the number of "Note:" messages when cross-compiling some STL
# stuff for ARM. See https://stackoverflow.com/questions/48149323/strange-gcc-warning-when-compiling-qt-project
# Basically, gcc 6 and gcc 7 are not ABI compatible, but since the whole OpenBMC
# project uses the same compiler, we can safely ignore these info notes.
add_project_arguments('-Wno-psabi', language: 'cpp')

conf_data = configuration_data()
conf_data.set_quoted('SPDMD_VERSION', meson.project_version())
configure_file(
  output: 'config.h',
  configuration: conf_data
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
sdeventplus = dependency(
  'sdeventplus',
  fallback: ['sdeventplus', 'sdeventplus_dep'],
)
phosphor_dbus_interfaces = dependency(
  'phosphor-dbus-interfaces',
  fallback: ['phosphor-dbus-interfaces', 'phosphor_dbus_interfaces_dep'],
)

if comp.has_header('nlohmann/json.hpp')
  nlohmann_dep = declare_dependency()
else
  nlohmann_dep = dependency(
    'nlohmann-json',
    fallback: [ 'nlohmann-json', 'nlohmann_json_dep' ],
  )
endif

if comp.has_header('CLI/CLI.hpp')
  CLI11_dep = declare_dependency()
else
  CLI11_dep = dependency(
    'CLI11',
    fallback: [ 'CLI11', 'CLI11_dep' ],
  )
endif

subdir('libspdmcpp')
subdir('spdmd')

subdir('spdmcpp_emu')	#TODO separate repo
