# The libpacketcorrupt.so

## Description

This library has been created to simulate packet corruptions between MCTP and SPDM. The primary function of the library is to intercept the system calls read and write used to communicate between MCTP and SPDM. Leveraging the ldpreload technique, the library is preloaded before other libraries, allowing it to intercept these calls and introduce modifications to the transmitted packets. The primary objective of this library is to simulate data packet corruption between MCTP and SPDM for testing purposes. The principle of the library is shown in the diagram below.  

![Use case diagram](imgs/usecasediag.png "Use case diagram")


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
- *measdata*: Measurement data will be modified randomly


***MCTP_CORRUPT_RAND_LEVEL*** parameter will determine with what probability the packet may be corrupted if use syntax `m/n`, where:
- `m`: where m is the number of packets that will be modified in the sequence
- `n` is the length of the sequence

There is also an alternative syntax that allows you to specify exactly the packet numbers in the sequence that will be modified `a,b,c,...%n` where:
- `a b c ` where abc are the sequence numbers of the packets that will be modified.
- `n` is the length of the sequence


## Packet Dropping Configuration

The library also supports the option to drop certain packets based on their **EID** (Endpoint ID) and **command type**. This behavior can be configured via environment variables:

- **MCTP_CORRUPT_DROP_EIDS**: A comma-separated list of EID numbers. Example: `1,2,5`. If the packet's EID matches one in this list, the packet will be dropped.
  - If the list starts with `!`, for example `!1,2,5`, packets **not** matching these EIDs will be dropped, while those matching will be allowed.
  
- **MCTP_CORRUPT_TYPES**: A comma-separated list of command types. Example: `1,2,3`. If the packet's type matches one in this list, it will be dropped.
  - If the list starts with `!`, for example `!1,2,3`, packets **not** matching these types will be dropped.

**Important**: If the file `/tmp/corrupt_drop_enable` exists, the packet drop mechanism is activated. If the file does not exist, packet dropping is disabled.




## Example usage

To configure the library to modify the size in 2 of the 10 packages, configure it as follows:
```
export MCTP_CORRUPT_MODE=msglen
export MCTP_CORRUPT_RAND_LEVEL='2/10'
LD_PRELOAD=libpacketcorrupt.so spdmd -v 7
```

To configure the library so that packages numbered 6 and 7 of 8 have a modified version header, configure it as follows
```
export MCTP_CORRUPT_MODE=version
export MCTP_CORRUPT_RAND_LEVEL='6,7,8%10'
LD_PRELOAD=libpacketcorrupt.so spdmd -v 7
```

To configure the library to drop packets with EID 1 and 2 and command types 3 and 4, but only if the `/tmp/corrupt_drop_enable` file exists:

```bash
export MCTP_CORRUPT_DROP_EIDS='1,2'
export MCTP_CORRUPT_TYPES='3,4'
touch /tmp/corrupt_drop_enable
LD_PRELOAD=libpacketcorrupt.so spdmd -v 7
```