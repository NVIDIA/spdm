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

// MCTP internal defs

enum mctp_offsets
{
    mctp_offs_hdr = 0,
    mctp_offs_eid = 1,
    mctp_offs_type = 2,
    mctp_offs_vers = 3,
    mctp_offs_code = 4,
    mctp_offs_arg1 = 5,
    mctp_offs_arg2 = 6,
    mctp_offs_mresp_record = 11,
};

enum mctp_type
{
    mctp_type_spdm = 5,
};

enum mctp_resp_code
{
    mctp_resp_diggest = 0x01,
    mctp_resp_cert = 0x02,
    mctp_resp_version = 0x04,
    mctp_resp_capab = 0x61,
    mctp_resp_algo = 0x63,
    mctp_resp_meas = 0x60,
};
