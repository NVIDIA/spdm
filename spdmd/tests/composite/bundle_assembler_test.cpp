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

// Unit tests for BundleAssembler — tag-602 structure, bstr-wrapped
// main-token, and the env.* -> bstr.cbor detached Claims-Set map.

#include "cbor_test_util.hpp"
#include "composite/bundle_assembler.hpp"

#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace spdmd::composite
{
namespace
{

TEST(BundleAssembler, Tag602Structure)
{
    std::vector<std::uint8_t> token{0xD8, 0x3D, 0x84}; // pretend EAT bytes
    std::vector<std::pair<std::string, std::vector<std::uint8_t>>> cs;
    cs.emplace_back("env.nic.0", std::vector<std::uint8_t>{0xA1, 0x01});
    cs.emplace_back("env.gpu.0", std::vector<std::uint8_t>{0xA1, 0x02});

    auto bundle = assembleBundle(token, cs);
    auto root = cbortest::decode(bundle);

    ASSERT_TRUE(root->isTag());
    EXPECT_EQ(root->tag, kCborTagDetachedEatBundle);

    auto arr = root->tagged;
    ASSERT_TRUE(arr->isArray());
    ASSERT_EQ(arr->array.size(), 2u);

    // [0] main-token wrapped as bstr.
    ASSERT_TRUE(arr->array[0]->isBytes());
    EXPECT_EQ(arr->array[0]->bytes, token);

    // [1] detached-claims-sets map.
    auto csMap = arr->array[1];
    ASSERT_TRUE(csMap->isMap());
    EXPECT_EQ(csMap->map.size(), 2u);
}

TEST(BundleAssembler, ClaimsSetsBstrWrappedAndKeyedByEnv)
{
    std::vector<std::uint8_t> token{0x01};
    std::vector<std::uint8_t> gpuCs{0xA1, 0x02, 0x03};
    std::vector<std::pair<std::string, std::vector<std::uint8_t>>> cs;
    cs.emplace_back("env.gpu.0", gpuCs);

    auto bundle = assembleBundle(token, cs);
    auto root = cbortest::decode(bundle);
    auto csMap = root->tagged->array[1];

    auto entry = csMap->atText("env.gpu.0");
    ASSERT_TRUE(entry && entry->isBytes());
    // The value is bstr .cbor: its content is exactly the Claims-Set
    // bytes (the digested bytes), not re-encoded.
    EXPECT_EQ(entry->bytes, gpuCs);
}

TEST(BundleAssembler, MapKeysDeterministicallyOrdered)
{
    std::vector<std::uint8_t> token{0x01};
    std::vector<std::pair<std::string, std::vector<std::uint8_t>>> cs;
    // Insert out of order.
    cs.emplace_back("env.nic.0", std::vector<std::uint8_t>{0x01});
    cs.emplace_back("env.gpu.0", std::vector<std::uint8_t>{0x02});
    cs.emplace_back("env.cpu.0", std::vector<std::uint8_t>{0x03});

    auto bundle = assembleBundle(token, cs);
    auto root = cbortest::decode(bundle);
    auto csMap = root->tagged->array[1];
    ASSERT_EQ(csMap->map.size(), 3u);
    // All same length; bytewise ascending: cpu < gpu < nic.
    EXPECT_EQ(csMap->map[0].first->text, "env.cpu.0");
    EXPECT_EQ(csMap->map[1].first->text, "env.gpu.0");
    EXPECT_EQ(csMap->map[2].first->text, "env.nic.0");
}

TEST(BundleAssembler, EmptyClaimsSetsProducesEmptyMap)
{
    std::vector<std::uint8_t> token{0x01};
    std::vector<std::pair<std::string, std::vector<std::uint8_t>>> cs;
    auto bundle = assembleBundle(token, cs);
    auto root = cbortest::decode(bundle);
    EXPECT_TRUE(root->tagged->array[1]->isMap());
    EXPECT_EQ(root->tagged->array[1]->map.size(), 0u);
}

} // namespace
} // namespace spdmd::composite
