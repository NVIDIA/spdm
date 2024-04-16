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

// Corrupted packet response code
int corrupt_pkt_mod_cmd(char* buf, size_t len) EXPORT_HIDDEN;

// Corrupted packet response code
int corrupt_pkt_mod_len(char* buf, size_t buf_size, size_t recv_size) EXPORT_HIDDEN;

// Corrupt message version
int corrupt_pkt_mod_version(char* buf, size_t len) EXPORT_HIDDEN;

// Corrupt reserved fields settings
int corrupt_pkt_mod_param_and_reserved(char* buf, size_t len, bool* modified) EXPORT_HIDDEN;

// Corrupt Certificate sizes
int corrupt_pkt_mod_cert_sizes(char* buf, size_t len) EXPORT_HIDDEN;

// Corrupt Certificate data
int corrupt_pkt_mod_cert_data(char* buf, size_t len) EXPORT_HIDDEN;

// Corrupt Unsupported algo fields
int corrupt_pkt_mod_unsup_algo(char* buf, size_t len) EXPORT_HIDDEN;

// Corrupt Unsupported capabilities fields
int corrupt_pkt_mod_unsup_capab(char* buf, size_t len) EXPORT_HIDDEN;

// pkt corrupt version reserved
int corrupt_pkt_mod_version_param_reserved(char *buf, size_t len) EXPORT_HIDDEN;

// pkt corrupt capabilities reserved
int corrupt_pkt_mod_capabilities_param_reserved(char *buf, size_t len) EXPORT_HIDDEN;

// pkt corrupt algo reserved
int corrupt_pkt_mod_algo_param_reserved(char *buf, size_t len) EXPORT_HIDDEN;
