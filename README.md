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

### Testing with SPDM emulator in qemu

Make sure that the current date and time is set properly. 
This is required for proper certificates verification.

     root@hgx:~# date
     Wed Feb  2 15:54:11 UTC 2022

If the date is not proper then set it, for example:

     date --set "2022-02-02 09:30"

Use modified MCTP service for MCTP control daemon to support local MCTP endpoints, for example:
https://gitlab-collab-01.nvidia.com/viking-team/libmctp, branch=topic/conclusive/spdm
Then run MCTP service pointing local EID endpoints used by SPDM responder emulator over MCTP:

     MCTP_CTRL_OPTS= -m 1 -t 2 -d 20 -v 1 -u14:5

Option -u, provides EID value and after ':' supported MCTP messages types, 5 is reserved for SPDM.
It is possible to provide many -u options.
This is mandatory for SPDM daemon tests, because it checks MCTP control sdbus for SPDM responders supporting MCTP SPDM messages.

Check that added MCTP endpoint values are reflected in MCTP sdbus objects:

     busctl tree xyz.openbmc_project.MCTP.Control

Use SPDM responder emulator from DMTF with a modification letting using MCTP socket, instead of a general socket:
https://gitlab.conclusive.pl/nvidia/spdm-emu.git, branch=main

Run the DMTF SPDM responder emulator with chosen options, for example:

    cd /usr/share/spdm-emu/
    ./spdm_responder_emu --trans MCTP_DEMUX --ver 1.1 --eid 16

Or if it is already setup as a service, then:

    systemctl start spdm_responder_emu.service
    systemctl stop spdm_responder_emu.service

It is possible to run more then one DMTF SPDM responder emulator.
Other possible options for spdm_responder_emu:

     --hash SHA_256/384/512
     --asym ECDSA_P256/P384/P521
 
 Next, run SPDM requester emulator, for example:

     spdmcpp_requester_emu --trans MCTP_DEMUX --eid 14
