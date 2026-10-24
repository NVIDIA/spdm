# SPDX-License-Identifier: MIT
#
# Meson build file for Intel tinycbor (Concise Binary Object
# Representation library — RFC 8949). Used as a packagefile patch
# because upstream only ships Makefiles.

project(
    'tinycbor',
    'c',
    version: '0.6.0',
    license: 'MIT',
    default_options: ['c_std=c11'],
)

tinycbor_sources = files(
    'src/cborencoder.c',
    'src/cborencoder_close_container_checked.c',
    'src/cborencoder_float.c',
    'src/cborerrorstrings.c',
    'src/cborparser.c',
    'src/cborparser_float.c',
    'src/cborvalidation.c',
    'src/cbortojson.c',
    'src/cborpretty.c',
)

tinycbor_inc = include_directories('src')

tinycbor_lib = static_library(
    'tinycbor',
    tinycbor_sources,
    include_directories: tinycbor_inc,
    install: false,
)

tinycbor_dep = declare_dependency(
    include_directories: tinycbor_inc,
    link_with: tinycbor_lib,
)
