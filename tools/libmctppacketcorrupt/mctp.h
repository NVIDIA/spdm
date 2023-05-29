#pragma once

// MCTP internal defs


enum mctp_offsets {
    mctp_offs_eid =  0,
    mctp_offs_type = 1,
    mctp_offs_vers = 2,
    mctp_offs_code = 3,
    mctp_offs_arg1 = 4,
    mctp_offs_arg2 = 5,
};


enum mctp_type {
    mctp_type_spdm = 5,
};

enum mctp_resp_code {
    mctp_resp_diggest       = 0x01,
    mctp_resp_cert          = 0x02,
    mctp_resp_version       = 0x04,
    mctp_resp_capab         = 0x61,
    mctp_resp_algo          = 0x63
};

