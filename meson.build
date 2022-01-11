project('spdmcpp',
	'cpp',
	version: '0.1',
	meson_version: '>=0.56.2',
	default_options: ['cpp_std=c++20', 'warning_level=3', 'werror=true']
)

if get_option('tests').enabled()
	gtest = dependency('gtest', main: true, disabler: true, required: false)
	gmock = dependency('gmock', disabler: true, required: false)
	assert(gtest.found(), 'Couldn\'t find gtest, either provide or disable tests with: -Dtests=disabled')
	assert(gmock.found(), 'Couldn\'t find gmock, either provide or disable tests with: -Dtests=disabled')
endif


add_global_arguments('-Wno-error=stringop-overflow', language: 'cpp')	#fmt throws these:
# [nix-shell:~/Projects/conclusive/nvidia-openbmc/spdmcpp/build]$ meson compile
# ninja: Entering directory `.'
# [1/8] Compiling C++ object subprojects/fmt/libcm_fmt.a.p/src_format.cc.o
# FAILED: subprojects/fmt/libcm_fmt.a.p/src_format.cc.o 
# g++ -Isubprojects/fmt/libcm_fmt.a.p -Isubprojects/fmt -I../subprojects/fmt -I../subprojects/fmt/include -Isubprojects/fmt/__CMake_build -I../subprojects/fmt/__CMake_build -fdiagnostics-color=always --coverage -pipe -D_FILE_OFFSET_BITS=64 -Wall -Winvalid-pch -Wnon-virtual-dtor -Wextra -Wpedantic -Werror -std=gnu++11 -g -fPIC -O3 -DNDEBUG -fvisibility=hidden -fvisibility-inlines-hidden -DFMT_LOCALE -MD -MQ subprojects/fmt/libcm_fmt.a.p/src_format.cc.o -MF subprojects/fmt/libcm_fmt.a.p/src_format.cc.o.d -o subprojects/fmt/libcm_fmt.a.p/src_format.cc.o -c ../subprojects/fmt/src/format.cc
# In file included from ../subprojects/fmt/include/fmt/format-inl.h:29,
#                  from ../subprojects/fmt/src/format.cc:8:
# In function ‘Char* fmt::v8::detail::format_uint(Char*, UInt, int, bool) [with unsigned int BASE_BITS = 4; Char = char; UInt = long unsigned int]’,
#     inlined from ‘It fmt::v8::detail::format_uint(It, UInt, int, bool) [with unsigned int BASE_BITS = 4; Char = char; It = fmt::v8::appender; UInt = long unsigned int]’ at ../subprojects/fmt/include/fmt/format.h:1183:25,
#     inlined from ‘fmt::v8::detail::write_ptr<char, fmt::v8::appender, long unsigned int>::<lambda(fmt::v8::detail::reserve_iterator<fmt::v8::appender>)>’ at ../subprojects/fmt/include/fmt/format.h:1374:32,
#     inlined from ‘OutputIt fmt::v8::detail::write_ptr(OutputIt, UIntPtr, const fmt::v8::basic_format_specs<Char>*) [with Char = char; OutputIt = fmt::v8::appender; UIntPtr = long unsigned int]’ at ../subprojects/fmt/include/fmt/format.h:1377:31:
# ../subprojects/fmt/include/fmt/format.h:1146:15: error: writing 1 byte into a region of size 0 [-Werror=stringop-overflow=]
#  1146 |     *--buffer = static_cast<Char>(BASE_BITS < 4 ? static_cast<char>('0' + digit)
#       |     ~~~~~~~~~~^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#  1147 |                                                 : digits[digit]);
#       |                                                 ~~~~~~~~~~~~~~~~
# ../subprojects/fmt/include/fmt/format.h: In function ‘OutputIt fmt::v8::detail::write_ptr(OutputIt, UIntPtr, const fmt::v8::basic_format_specs<Char>*) [with Char = char; OutputIt = fmt::v8::appender; UIntPtr = long unsigned int]’:
# ../subprojects/fmt/include/fmt/format.h:1182:8: note: at offset -1 to object ‘buffer’ with size 17 declared here
#  1182 |   char buffer[num_bits<UInt>() / BASE_BITS + 1];
#       |        ^~~~~~



# libspdmcpp_proj = subproject('libspdmcpp')
# libsimple_dep = libsimple_proj.get_variable('libsimple_dep')

sdbusplus = dependency(
  'sdbusplus',
  fallback: ['sdbusplus', 'sdbusplus_dep'],
)
sdeventplus = dependency(
  'sdeventplus',
  fallback: ['sdeventplus', 'sdeventplus_dep'],
)

comp = meson.get_compiler('cpp')
# mbedtls = dependency(
#   'mbedtls',
#   fallback: ['mbedtls', 'mbedtls_dep'],
# )
# mbedtls_dep = dependency('mbedtls')
# crypto_deps = [ dependency('libcrypto') ]
# crypto_deps += dependency('libssl')
# crypto_deps = dependency('openssl')
# crypto_deps = dependency('libmbedtls')
crypto_deps = declare_dependency(
# 	include_directories: 
	dependencies: [
# 		comp.find_library('mbedtls'),
		comp.find_library('mbedcrypto'),
		comp.find_library('mbedx509')
	]
)

# systemd = dependency('systemd')


subdir('libspdmcpp')
subdir('spdmcppd')

subdir('spdmcpp_emu')	#TODO separate repo
