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
#include <stddef.h>
#include <stdbool.h>
#include "apptypes.h"
#include "error.h"

//! Initialize corrupt library
int corrupt_init(void) EXPORT_HIDDEN;
//! Deinitialize corrupt library
int corrupt_deinit(void) EXPORT_HIDDEN;

/**
 * @param[in] buf Buffer data len
 * @param[in] buf_size Buffer maximum size
 * @param[in] recv_size Real recv size
*/
int corrupt_recv_packet(char *buf, size_t buf_size, size_t recv_size) EXPORT_HIDDEN;

