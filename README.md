# spdmcpp is a c++ implementation of the DMTF [SPDM](https://www.dmtf.org/standards/pmci) specification

Initial version

## Prerequisites

Main mandatoy dependencies for compilation:

     sudo apt-get install libmbedtls-dev

For testing purposes, the implementation uses Google Test (GTest). It is possible to install it using the below command (for ubuntu):

     sudo apt-get install libgtest-dev

## Build guidelines

rm -rf build/
meson build
cd build
ninja
./spdmcpp_emu/spdmcpp_requester_emu --help

### unit tests

meson configure -Db_coverage=true
ninja
ninja test
./spdmcpp_emu/spdmcpp_requester_emu #successful run against the responder-emulator greatly increases the test-coverage
ninja coverage-html
