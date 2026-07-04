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

// Unit test for composite::pemToDerConcat — round-trips a known DER cert
// through PEM and back, and concatenates a 2-cert chain.

#include "composite/pem.hpp"

#include <mbedtls/base64.h>

#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace spdmd::composite
{
namespace
{

std::string pemOf(const std::vector<std::uint8_t>& der)
{
    std::size_t n = 0;
    mbedtls_base64_encode(nullptr, 0, &n, der.data(), der.size());
    std::string b64(n, '\0');
    std::size_t w = 0;
    mbedtls_base64_encode(reinterpret_cast<unsigned char*>(b64.data()),
                          b64.size(), &w, der.data(), der.size());
    b64.resize(w);
    return "-----BEGIN CERTIFICATE-----\n" + b64 +
           "\n-----END CERTIFICATE-----\n";
}

TEST(Pem, SingleCertRoundTrips)
{
    std::vector<std::uint8_t> der{0x30, 0x82, 0x01, 0x02, 0xDE, 0xAD};
    auto out = pemToDerConcat(pemOf(der));
    EXPECT_EQ(out, der);
}

TEST(Pem, ConcatenatesChain)
{
    std::vector<std::uint8_t> a{0x30, 0x03, 0x01, 0x02, 0x03};
    std::vector<std::uint8_t> b{0x30, 0x02, 0xAA, 0xBB};
    auto out = pemToDerConcat(pemOf(a) + pemOf(b));
    std::vector<std::uint8_t> expect = a;
    expect.insert(expect.end(), b.begin(), b.end());
    EXPECT_EQ(out, expect);
}

TEST(Pem, EmptyOnNoCerts)
{
    EXPECT_TRUE(pemToDerConcat("no certs here").empty());
}

} // namespace
} // namespace spdmd::composite
