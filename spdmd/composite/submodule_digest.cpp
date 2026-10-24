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

#include "submodule_digest.hpp"

#include <mbedtls/md.h>

#include <stdexcept>
#include <string>
#include <utility>

namespace spdmd::composite
{

std::array<std::uint8_t, kSha384Len> sha384(std::span<const std::uint8_t> b)
{
    std::array<std::uint8_t, kSha384Len> out{};
    const mbedtls_md_info_t* info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
    if (info == nullptr)
    {
        throw std::runtime_error("SubmoduleDigest: SHA-384 is unavailable");
    }
    const int rc = mbedtls_md(info, b.data(), b.size(), out.data());
    if (rc != 0)
    {
        throw std::runtime_error("SubmoduleDigest: SHA-384 failed: " +
                                 std::to_string(rc));
    }
    return out;
}

SubmoduleRecord makeSubmoduleRecord(std::string environmentId,
                                    std::span<const std::uint8_t> claimsSet)
{
    SubmoduleRecord r;
    r.environmentId = std::move(environmentId);
    r.hashAlgId = kCoseAlgSha384;
    r.digest = sha384(claimsSet);
    return r;
}

} // namespace spdmd::composite
