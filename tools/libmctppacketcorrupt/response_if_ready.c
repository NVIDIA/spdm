/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
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

/* Currrently we are supporting only one token, layer
  we can improve the library for support more tokens
*/
#include "response_if_ready.h"

#include "mctp.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Not ready error code
#define ERR_RESP_NOT_RDY_CODE 0x42
// Not ready error data (reserved)
#define ERR_RESP_NOT_RDY_DATA 0x00
// Define response delay 2*22 (~4 sec)
#define ERR_RESP_NOT_RDY_RTD_EXP 22
// Error delayed response token
#define ERR_RESP_NOT_RDY_TOKEN 0x55
// Define response delay multiplier x2
#define ERR_RESP_NOT_RDY_RDTM 2
// minimal sleep time

// Return response if ready packet and store it locally
int corrupt_pkt_mod_error_response_not_ready(corrupt_context* ctx, char* buf,
                                             size_t len)
{
    if (len < mctp_offs_code)
    {
        return error_buf_offs;
    }
    if (ctx->saved_response_if_rdy_ptr)
    {
        return error_buf_multi_rdy_not_supported;
    }
    ctx->saved_response_if_rdy_ptr = malloc(len);
    assert(ctx->saved_response_if_rdy_ptr);
    memcpy(ctx->saved_response_if_rdy_ptr, buf, len);
    const uint8_t msg_code = buf[mctp_offs_code];
    const uint8_t error_resp[] = {mctp_resp_error,
                                  ERR_RESP_NOT_RDY_CODE,
                                  ERR_RESP_NOT_RDY_DATA,
                                  ERR_RESP_NOT_RDY_RTD_EXP,
                                  msg_code,
                                  ERR_RESP_NOT_RDY_TOKEN,
                                  ERR_RESP_NOT_RDY_RDTM};
    ctx->saved_response_if_rdy_len = len;
    ctx->saved_response_if_rdy_fd = INVALID_VALUE;
    memcpy(&buf[mctp_offs_code], error_resp, sizeof(error_resp));
    return mctp_offs_code + sizeof(error_resp);
}

// Return resumed packet if response not ready match
int corrupt_pkt_mod_error_response_is_ready(int sockfd, corrupt_context* ctx,
                                            const char* buf, size_t len)
{
    // We don't have any stored response (ignore)
    if (!ctx->saved_response_if_rdy_ptr)
    {
        fprintf(stderr,
                "### We don't have any stored packet for RESPOND_IF_READY\n");
        return 0;
    }
    if (ctx->saved_response_if_rdy_len < mctp_offs_code)
    {
        fprintf(stderr, "### Response len to short for RESPOND_IF_READY\n");
        return 0;
    }
    if (len < mctp_offs_arg2)
    {
        fprintf(stderr, "### Response req to short for RESPOND_IF_READY\n");
        return 0;
    }
    // Request code checking
    if (buf[mctp_offs_arg1] ==
        (ctx->saved_response_if_rdy_ptr[mctp_offs_arg1] ^ 0x80))
    {
        fprintf(stderr, "### RESPOND_IF_READY expect cmd: %02x stored: %02x\n",
                buf[mctp_offs_arg1],
                ctx->saved_response_if_rdy_ptr[mctp_offs_arg1]);
        errno = -EINVAL;
        free(ctx->saved_response_if_rdy_ptr);
        ctx->saved_response_if_rdy_ptr = NULL;
        ctx->saved_response_if_rdy_len = 0;
        return -1;
    }
    // Token checking
    if (buf[mctp_offs_arg1] == ctx->saved_response_if_rdy_ptr[mctp_offs_arg1])
    {
        fprintf(stderr, "### RESPOND_IF_READY expect token: %02x got: %02x\n",
                ERR_RESP_NOT_RDY_TOKEN, buf[mctp_offs_arg2]);
        errno = -EINVAL;
        free(ctx->saved_response_if_rdy_ptr);
        ctx->saved_response_if_rdy_ptr = NULL;
        ctx->saved_response_if_rdy_len = 0;
        return -1;
    }
    // Notify that respond if ready packet received
    ctx->saved_response_if_rdy_fd = sockfd;
    return len;
}

// Fake recv in case response if ready
int corrupt_pkt_mod_error_resp_fake_recv(int sockfd, corrupt_context* ctx,
                                         char* buf, size_t buf_size)

{
    if (sockfd == ctx->saved_response_if_rdy_fd)
    {
        if (buf_size < ctx->saved_response_if_rdy_len)
        {
            errno = E2BIG;
            return INVALID_VALUE;
        }
        memcpy(buf, ctx->saved_response_if_rdy_ptr,
               ctx->saved_response_if_rdy_len);
        free(ctx->saved_response_if_rdy_ptr);
        ctx->saved_response_if_rdy_ptr = NULL;
        const int rlen = ctx->saved_response_if_rdy_len;
        ctx->saved_response_if_rdy_len = 0;
        ctx->saved_response_if_rdy_fd = INVALID_VALUE;
        return rlen;
    }
    return 0;
}