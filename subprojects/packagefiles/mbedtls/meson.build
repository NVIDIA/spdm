project('mbedtls', 'c', version: '3.6.1', license: 'Apache-2.0')

cmake = import('cmake')

cmake_opts = cmake.subproject_options()
cmake_opts.add_cmake_defines(
    {
        'USE_SHARED_MBEDTLS_LIBRARY': 'ON',
        'ENABLE_TESTING': 'OFF',
        'MBEDTLS_FATAL_WARNINGS': 'OFF',
    },
)

mbedtls_proj = cmake.subproject('mbedtls', options: cmake_opts)

# Export the libraries as dependencies
mbedcrypto_dep = mbedtls_proj.dependency('mbedcrypto')
mbedx509_dep = mbedtls_proj.dependency('mbedx509')
mbedtls_dep = mbedtls_proj.dependency('mbedtls')

# Make them available to parent project
meson.override_dependency('mbedcrypto', mbedcrypto_dep)
meson.override_dependency('mbedx509', mbedx509_dep)
meson.override_dependency('mbedtls', mbedtls_dep)

