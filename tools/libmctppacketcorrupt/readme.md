# The libpacketcorrupt.so

## Description

This library has been created to simulate packet corruptions between MCTP and SPDM. The primary function of the library is to intercept the system calls read and write used to communicate between MCTP and SPDM. Leveraging the ldpreload technique, the library is preloaded before other libraries, allowing it to intercept these calls and introduce modifications to the transmitted packets. The primary objective of this library is to simulate data packet corruption between MCTP and SPDM for testing purposes. The principle of the library is shown in the diagram below.  

![Use case diagram](/imgs/usecasediag.png "Use case diagram")


The library will read configuration data from two system variables ***MCTP_CORRUPT_MODE*** and ***MCTP_CORRUPT_RAND_LEVEL***  parameter will determine which field of the packet was corrupted:

- *bypass*: Message is passed to the real caller without any modification
- *command*: Command code is corrupted
- *reserved*: Reserved fields are not empty
- *msglen*: Actual response message length is less/greater than the given length in the message
- *zerolen*: Message len is truncated to zerjjkko
- *version*: SPDM message version header is modified
- *certlen*: Certyficate len field is corrupted
- *certdata*: Certifcate data are corrupted
- *unsupalgo*: Algoritm fields are corrupted
- *unsupcapab*: Capabilities fields are corrupted
- *versionfields*: Get versions fields param1, param2, reserved are modified
- *capabfields*: Get capabilities fields param1, param2, reserved are modified
- *digestfields*: Get Digest fields param1, param2, reserved are modified
- *certfields*: Get Cert fields param1, param2, reserved are modified
- *algofields*: Get Algo fields param1, param2, reserved are modified


***MCTP_CORRUPT_RAND_LEVEL*** parameter will determine with what probability the packet may be corrupted if use syntax `m/n`, where:
- `m`: where m is the number of packets that will be modified in the sequence
- `n` is the length of the sequence

There is also an alternative syntax that allows you to specify exactly the packet numbers in the sequence that will be modified `a,b,c,...%n` where:
- `a b c ` where abc are the sequence numbers of the packets that will be modified.
- `n` is the length of the sequence

## Example usage

To configure the library to modify the size in 2 of the 10 packages, configure it as follows:
```
export MCTP_CORRUPT_MODE=msglen
export MCTP_CORRUPT_RAND_LEVEL='2/10'
LD_LIBRARY_PATH=libpacketcorrupt.so spdmd -v 7
```

To configure the library so that packages numbered 6 and 7 of 8 have a modified version header, configure it as follows
```
export MCTP_CORRUPT_MODE=version
export MCTP_CORRUPT_RAND_LEVEL='6,7,8%10'
LD_LIBRARY_PATH=libpacketcorrupt.so spdmd -v 7
```
