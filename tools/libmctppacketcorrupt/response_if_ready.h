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

#include <stdbool.h>
#include <stddef.h>

// Return response not ready error
int corrupt_pkt_mod_error_response_not_ready(corrupt_context* ctx, char* buf,
                                             size_t len) EXPORT_HIDDEN;

// Return resumed packet if response not ready match
int corrupt_pkt_mod_error_response_is_ready(int sockfd, corrupt_context* ctx,
                                            const char* buf,
                                            size_t len) EXPORT_HIDDEN;

// Fake recv in case response if ready
int corrupt_pkt_mod_error_resp_fake_recv(int sockfd, corrupt_context* ctx,
                                         char* buf,
                                         size_t buf_size) EXPORT_HIDDEN;