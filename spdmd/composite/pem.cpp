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

#include "pem.hpp"

#include <mbedtls/base64.h>

#include <string>

namespace spdmd::composite
{

std::vector<std::uint8_t> pemToDerConcat(std::string_view pem)
{
    static constexpr std::string_view kBegin = "-----BEGIN CERTIFICATE-----";
    static constexpr std::string_view kEnd = "-----END CERTIFICATE-----";

    std::vector<std::uint8_t> out;
    std::size_t pos = 0;
    while (pos < pem.size())
    {
        const auto begin = pem.find(kBegin, pos);
        if (begin == std::string_view::npos)
        {
            break;
        }
        const auto end = pem.find(kEnd, begin);
        if (end == std::string_view::npos)
        {
            break;
        }
        std::string b64;
        b64.reserve(end - begin);
        for (std::size_t i = begin + kBegin.size(); i < end; ++i)
        {
            const char c = pem[i];
            if (c != '\n' && c != '\r' && c != ' ' && c != '\t')
            {
                b64.push_back(c);
            }
        }
        std::size_t derLen = 0;
        mbedtls_base64_decode(
            nullptr, 0, &derLen,
            reinterpret_cast<const unsigned char*>(b64.data()), b64.size());
        if (derLen > 0)
        {
            const std::size_t before = out.size();
            out.resize(before + derLen);
            std::size_t written = 0;
            if (mbedtls_base64_decode(
                    out.data() + before, derLen, &written,
                    reinterpret_cast<const unsigned char*>(b64.data()),
                    b64.size()) == 0)
            {
                out.resize(before + written);
            }
            else
            {
                out.resize(before);
            }
        }
        pos = end + kEnd.size();
    }
    return out;
}

} // namespace spdmd::composite
