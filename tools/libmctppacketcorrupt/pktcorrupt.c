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



#include "apptypes.h"
#include "userio.h"
#include "pktcorrupt.h"
#include "random.h"
#include "mctp.h"
#include "pktmod.h"
#include <stdio.h>

// Library configuration
static corrupt_context app_context;

// Return true if the packet should be modifed
static bool is_packet_should_be_modifed(const corrupt_context* ctx, const char* buf, size_t len)
{
    bool found = false;
    // Check if should be modified according to the limit
    for(size_t i=0; i<ctx->cfg.pkt_corrupted; ++i)
    {
        const u32 pkt = ctx->pkt_mod_num[i];
        if(pkt == ctx->pkt_counter) {
            found = true;
            break;
        }
    }
    if(!found) {
        return false;
    }
    if(len < mctp_offs_code) {
        return false;
    }
    // Skip if selected packed doesn't match the response
    const u8 mresp = (u8)buf[mctp_offs_code];
    if(ctx->cfg.mode == corrupt_mode_unsup_algo && mresp != mctp_resp_algo) {
        return false;
    }
    if(ctx->cfg.mode == corrupt_mode_unsup_capab && mresp != mctp_resp_capab) {
        return false;
    }
    if(ctx->cfg.mode == corrupt_mode_cert_len && mresp != mctp_resp_cert) {
        return false;
    }
    if(ctx->cfg.mode == corrupt_mode_cert_data && mresp != mctp_resp_cert) {
        return false;
    }
    if(ctx->cfg.mode == corrupt_mode_version_fields && mresp != mctp_resp_version) {
        return false;
    }
    if(ctx->cfg.mode == corrupt_mode_capab_fields && mresp != mctp_resp_capab) {
        return false;
    }
    if(ctx->cfg.mode == corrupt_mode_digest_fields && mresp != mctp_resp_diggest) {
        return false;
    }
    if(ctx->cfg.mode == corrupt_mode_cert_fields && mresp != mctp_resp_cert) {
        return false;
    }
    if(ctx->cfg.mode == corrupt_mode_algo_fields && mresp != mctp_resp_algo) {
        return false;
    }
    return true;
}

// Randomize packet num for modify
static int packet_num_update(corrupt_context* ctx)
{
    if(ctx->pkt_counter == 0 && !ctx->cfg.pkt_manual_list)
    {
        // Fill with next numbers
		u16* const arr = ctx->pkt_mod_num;
		const size_t n = ctx->cfg.pkt_cycles;
        for(size_t i=0; i<n; ++i) {
            arr[i] = i;
        }
		// Randomize array
		for (size_t i = 0; i < n; i++) {
			u32 rand_val = 0;
			if(random_value(&rand_val)<0) {
				return error_failure;
			}
			u32 j = rand_val % n;
			u32 temp = arr[i];
			arr[i] = arr[j];
			arr[j] = temp;
		}
    }
    if( ctx->pkt_counter == 0 ) {
		u16* const arr = ctx->pkt_mod_num;
        fprintf(stderr,"## Pkt nums will be updated: ");
		for (size_t i = 0; i < ctx->cfg.pkt_corrupted; i++) {
            fprintf(stderr, "%i, ", arr[i]);
        }
        fprintf(stderr," ##\n");
    }
	if(++ctx->pkt_counter >= ctx->cfg.pkt_cycles) {
		ctx->pkt_counter = 0;
	}
    return error_success;
}

// Modify buffer context per type
static int packet_modify_buffer(const corrupt_context* ctx, char* buf, size_t buf_size, size_t recv_size, bool* modified)
{
    switch(ctx->cfg.mode) {
    case corrupt_mode_cmds:
        *modified = true;
        return corrupt_pkt_mod_cmd(buf, recv_size);
    case corrupt_mode_reserved:
        return corrupt_pkt_mod_param_and_reserved(buf, recv_size, modified);
    case corrupt_mode_msg_zero:
        *modified = true;
        return 0;
    case corrupt_mode_msg_len:
        *modified = true;
        return corrupt_pkt_mod_len(buf, buf_size, recv_size);
    case corrupt_mode_version:
        *modified = true;
        return corrupt_pkt_mod_version(buf, recv_size);
    case corrupt_mode_cert_data:
        *modified = true;
        return corrupt_pkt_mod_cert_data(buf, recv_size);
    case corrupt_mode_cert_len:
        *modified = true;
        return corrupt_pkt_mod_cert_sizes(buf, recv_size);
    case corrupt_mode_unsup_algo:
        *modified = true;
        return corrupt_pkt_mod_unsup_algo(buf, recv_size);
    case corrupt_mode_unsup_capab:
        *modified = true;
        return corrupt_pkt_mod_unsup_capab(buf, recv_size);
    case corrupt_mode_version_fields:
        *modified = true;
        return corrupt_pkt_mod_version_param_reserved(buf, recv_size);
    case corrupt_mode_capab_fields:
        *modified = true;
        return corrupt_pkt_mod_capabilities_param_reserved(buf, recv_size);
    case corrupt_mode_digest_fields:
        return corrupt_pkt_mod_param_and_reserved(buf, recv_size, modified);
    case corrupt_mode_cert_fields:
        *modified = true;
        return corrupt_pkt_mod_capabilities_param_reserved(buf, recv_size);
    case corrupt_mode_algo_fields:
        *modified = true;
        return corrupt_pkt_mod_algo_param_reserved(buf, recv_size);
    default:
        return recv_size;
    }
}


// Initialize library
int corrupt_init(void)
{
    int err = userio_read_lib_config(&app_context.cfg);
    if(err<0) {
        userio_print_help();
        return err;
    }
    err = random_init();
    if(app_context.cfg.pkt_manual_list) {
        for(u32 i=0; i<app_context.cfg.pkt_corrupted; ++i) {
            app_context.pkt_mod_num[i] = app_context.cfg.pkt_mod_num[i];
        }
    }
    if(err<0) return err;
    app_context.pkt_counter = 0;
    err = packet_num_update(&app_context);
    if(err<0) return err;
    app_context.pkt_counter = 0;
    return error_success;
}

// Deinitialize library
int corrupt_deinit(void)
{
    random_deinit();
    return error_success;
}

// Core function for parse packets
int corrupt_recv_packet(char *buf, size_t buf_size, size_t recv_size)
{
    int ret_val = (int)recv_size;
    if(app_context.cfg.mode == corrupt_mode_bypass) {
        return ret_val;
    }
    bool modified = false;
    if(is_packet_should_be_modifed(&app_context, buf, recv_size)) {
        ret_val = packet_modify_buffer(&app_context, buf, buf_size, recv_size, &modified);
        if(ret_val<0) {
            return ret_val;
        }
    }
    fprintf(stderr,"## Packet: %u/%u modified: %i ###\n",
        app_context.pkt_counter, app_context.cfg.pkt_cycles, modified);
    const int err = packet_num_update(&app_context);
    if(err<0) {
        return err;
    }
    return ret_val;
}

