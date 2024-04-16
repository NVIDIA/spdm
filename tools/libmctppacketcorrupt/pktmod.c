/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */





#include <stdio.h>

#include "pktmod.h"
#include "mctp.h"
#include "random.h"
#include "apptypes.h"
#include "error.h"

// Corrupted packet response code
int corrupt_pkt_mod_cmd(char* buf, size_t len)
{
    u32 rand_val = 0;
    int error = random_value(&rand_val);
    if(error) {
        return error;
    }
    buf[mctp_offs_code] =  rand_val;
    return len;
}

// Corrupted packet response code
int corrupt_pkt_mod_len(char* buf, size_t buf_size, size_t recv_size)
{
    (void)buf;
    (void)recv_size;
    u32 rand_val = 0;
    int error = random_value(&rand_val);
    if(error) {
        return error;
    }
    return rand_val % (buf_size);
}


// Corrupt message version
int corrupt_pkt_mod_version(char* buf, size_t len)
{
    u32 rand_val = 0;
    int error = random_value(&rand_val);
    if(error) {
        return error;
    }
    buf[mctp_offs_vers] = rand_val;
    return len;
}


// Modify reserved fields helper function
static int modify_reserved_fields(char* buf, size_t len, size_t n1, size_t size)
{
    const size_t n2 = n1 + size;
    if(len < mctp_offs_arg1 + n2 ) {
        return error_buf_offs;
    }
    for(u32 i=n1; i<n2; ++i) {
        buf[mctp_offs_arg1+i] = 0x55;
    }
    return len;
}


// Corrupt reserved fields settings
int corrupt_pkt_mod_param_and_reserved(char* buf, size_t len, bool* modified)
{
    const u8 code = buf[mctp_offs_code];
    switch(code) {
        case mctp_resp_version:
            *modified = true;
            return modify_reserved_fields(buf, len, 0, 3);
        case mctp_resp_capab:
            *modified = true;
            modify_reserved_fields(buf, len, 0, 3);
            modify_reserved_fields(buf, len, 6, 2);
            return modify_reserved_fields(buf, len, 6, 2);
        case mctp_resp_diggest:
            *modified = true;
            return modify_reserved_fields(buf, len, 0, 1);
        case mctp_resp_cert:
            *modified = true;
            return modify_reserved_fields(buf, len, 1, 1);
        case mctp_resp_algo:
            *modified = true;
            modify_reserved_fields(buf, len, 3, 1);
            modify_reserved_fields(buf, len, 7, 1);
            modify_reserved_fields(buf, len, 20, 12);
            return modify_reserved_fields(buf, len, 34, 2);
        default:
            return len;
    }
}

// pkt corrupt version reserved
int corrupt_pkt_mod_version_param_reserved(char *buf, size_t len)
{
    u32 field_id;
    int error = random_value(&field_id);
    if(error) {
        return error;
    }
    return modify_reserved_fields(buf, len, field_id%3, 1);
}

// pkt corrupt capabilities reserved
int corrupt_pkt_mod_capabilities_param_reserved(char *buf, size_t len)
{
    u32 field_id;
    int error = random_value(&field_id);
    if(error) {
        return error;
    }
    field_id = field_id % 5;
    if(field_id <= 2) {
        return modify_reserved_fields(buf, len, field_id, 1);
    } else {
        field_id -= 3;
        return modify_reserved_fields(buf, len, field_id, 1);
    }
}


// pkt corrupt capabilities reserved
int corrupt_pkt_mod_algo_param_reserved(char *buf, size_t len)
{
    u32 field_id;
    int error = random_value(&field_id);
    if(error) {
        return error;
    }
    field_id = field_id % 16;

    if(field_id==0) {
        return modify_reserved_fields(buf, len, 3, 1);
    } else if(field_id==1) {
        return modify_reserved_fields(buf, len, 7, 1);
    } else if(field_id <= 2 + 12) {
        field_id -= 2;
        return modify_reserved_fields(buf, len, field_id, 12);
    } else if(field_id <= 15) {
        field_id -= 15;
        return modify_reserved_fields(buf, len, 34, 2);
    }
    return len;
}




// Corrupt Certificate sizes
int corrupt_pkt_mod_cert_sizes(char* buf, size_t len)
{
    u32 port_len, rem_len;
    int error = random_value(&port_len);
    if(error) {
        return error;
    }
    error = random_value(&rem_len);
    if(error) {
        return error;
    }
    static const u32 portion_len_offs = mctp_offs_vers + 4;
    static const u32 reminder_len_offs = mctp_offs_vers + 6;
    static const u32 reminder_len_end =  reminder_len_offs + 2;
    if(len < reminder_len_end) {
        return error_buf_offs;
    }
    u16* u16wr = (u16*)(buf+portion_len_offs);
    *u16wr = port_len;
    //u16wr = (u16*)(buf+reminder_len_offs);
    //*u16wr = rem_len;
    return len;
}

// Corrupt Certificate data
int corrupt_pkt_mod_cert_data(char* buf, size_t len)
{
    static const u32 cert_start_offs = mctp_offs_vers + 8;
    if(len < cert_start_offs+1) {
        return error_buf_offs;
    }
    u32 rand_value;
    int error = random_value(&rand_value);
    if(error) {
        return error;
    }
    buf[cert_start_offs + rand_value%(len-cert_start_offs-1)] = rand_value;
    return len;
}

// Corrupt Unsupported algo fields
int corrupt_pkt_mod_unsup_algo(char* buf, size_t len)
{
    u32 rand_val;
    int error = random_value(&rand_val);
    if(error) {
        return error;
    }
    static const u32 algo_offs = mctp_offs_vers + 8;
    static const u32 algo_end =  algo_offs + 4;
    if(len < algo_end) {
        return error_buf_offs;
    }
    u32* u32wr = (u32*)(buf+algo_offs);
    *u32wr = rand_val;
    return len;
}

// Corrupt Unsupported capabilities fields
int corrupt_pkt_mod_unsup_capab(char* buf, size_t len)
{
    u32 rand_len;
    int error = random_value(&rand_len);
    if(error) {
        return error;
    }
    static const u32 flags_offs = mctp_offs_vers + 8;
    static const u32 flags_end =  flags_offs + 4;
    if(len < flags_end) {
        return error_buf_offs;
    }
    u32* u32wr = (u32*)(buf+flags_offs);
    *u32wr = rand_len;
    return len;
}
