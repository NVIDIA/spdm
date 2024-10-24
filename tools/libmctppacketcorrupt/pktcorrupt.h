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

#pragma once
#include "apptypes.h"
#include "error.h"

#include <stdbool.h>
#include <stddef.h>

//! Initialize corrupt library
int corrupt_init(void) EXPORT_HIDDEN;

//! Deinitialize corrupt library
int corrupt_deinit(void) EXPORT_HIDDEN;

/**
 * @param[in] buf Buffer data len
 * @param[in] buf_size Buffer maximum size
 * @param[in] recv_size Real recv size
 */
int corrupt_recv_packet(char* buf, size_t buf_size,
                        size_t recv_size) EXPORT_HIDDEN;

/**
 * Check if particular received packet should be droppend or not
 * @param[in] eid Input eid
 * @param[in] type Message type code
 * @param[out] true if should be dropped , otherwise false
 */
bool corrupt_pkt_should_be_dropped(int eid, int type) EXPORT_HIDDEN;

/**
 * Check if the send functions should be handled internally
 * @note it is ussed to catch RESPOND_IF_READY packet and dont send it to
 * responder
 * @param[in] sockfd Calling socket responder for fill the pkt
 * @param[in] buf Buffer from send syscall
 * @param[in] buf_size Buffer size of oryginal packet
 * @return if 0 oryginal send should be called otherwise not
 */
int corrupt_send_packet(int sockfd, const char* buf,
                        size_t buf_size) EXPORT_HIDDEN;

/**
 * Return file descriptor if fake data is available
 * @return if positive file descriptor
 */
int corrupt_fake_fd_has_data(void) EXPORT_HIDDEN;

/**
 * @param[in] sockfd Input socket for receive data
 * @param[in] buf Receive buffer
 * @param[in] buf_Size Received buffer size
 * @return Received data if 0 if go to the normal recv
 */
int corrupt_fake_recv_packet(int sockfd, char* buf,
                             size_t buf_size) EXPORT_HIDDEN;