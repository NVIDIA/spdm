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

#pragma once
#include "config.h"
#include <stdint.h>
#include <stdbool.h>


// Rust types
typedef uint8_t u8;
typedef int8_t i8;
typedef uint16_t u16;
typedef int16_t i16;
typedef uint32_t u32;
typedef int32_t i32;
typedef uint64_t u64;
typedef int64_t i64;
typedef float f32;
typedef double f64;


// Faliure codes
enum error {
    error_success = 0,
    error_failure = -1,
    error_no_env_var = -2,
    error_env_parse = -3,
    error_env_range = -4,
    error_invalid_size = -5,
    error_buf_offs = -6,
};

// Working mode
typedef enum corrupt_mode  {
    corrupt_mode_invalid,           //! Configuration is invalid
    corrupt_mode_bypass,            //! Bypass do not modify packets
    corrupt_mode_cmds,              //! Wrong command
    corrupt_mode_reserved,          //! Reserved fields non empty
    corrupt_mode_msg_len,           //! Messsage length is invalid
    corrupt_mode_msg_zero,          //! Corrupt mode msg zero length
    corrupt_mode_version,           //! Message version is invald
    corrupt_mode_cert_len,          //! Certificate length is invalid
    corrupt_mode_cert_data,         //! Certificate data modified
    corrupt_mode_unsup_algo,        //! Unsupported algo
    corrupt_mode_unsup_capab,       //! Unsupported capabilities
    corrupt_mode_version_fields,    //! Corrupt mode version fields
    corrupt_mode_capab_fields,      //! Corrupt mode capabilities fields
    corrupt_mode_digest_fields,     //! Corrupt mode digest fields
    corrupt_mode_cert_fields,       //! Corrupt mode cert fields
    corrupt_mode_algo_fields,       //! Corrupt mode algorithm fields
} corrupt_mode;



// Corrupt config structure
typedef struct corrupt_config {
    enum corrupt_mode mode;     //! Packet corruption mode
    u32 pkt_corrupted;          //! Number of packet corrupted
    u32 pkt_cycles;             //! Number of packet cycles
    //! Packet numbers for corrupt from cmdline
    u16 pkt_mod_num[CONFIG_MAX_PKT_HISTORY];
    bool pkt_manual_list;   //! Packets to corrupt is manually provided
} corrupt_config;


// Corrrupt context
typedef struct corrupt_context {
    // Config structure
    corrupt_config cfg;
    // Current packet counter
    u16 pkt_mod_num[CONFIG_MAX_PKT_HISTORY];
    // Packet modifed number
    u32 pkt_counter;
} corrupt_context;


// Hidden visibility
#define EXPORT_HIDDEN  __attribute__((visibility("hidden")))
