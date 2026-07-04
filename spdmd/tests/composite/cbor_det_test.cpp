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

// Unit tests for the deterministic CBOR writer (composite::cbor).

#include "cbor_test_util.hpp"
#include "composite/cbor_det.hpp"

#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

namespace spdmd::composite::cbor
{
namespace
{

std::vector<std::uint8_t> bytes(std::initializer_list<std::uint8_t> l)
{
    return std::vector<std::uint8_t>(l);
}

TEST(CborDet, UintShortestForm)
{
    EXPECT_EQ(uintVal(0), bytes({0x00}));
    EXPECT_EQ(uintVal(23), bytes({0x17}));
    EXPECT_EQ(uintVal(24), bytes({0x18, 0x18}));
    EXPECT_EQ(uintVal(255), bytes({0x18, 0xFF}));
    EXPECT_EQ(uintVal(256), bytes({0x19, 0x01, 0x00}));
    EXPECT_EQ(uintVal(65535), bytes({0x19, 0xFF, 0xFF}));
    EXPECT_EQ(uintVal(65536), bytes({0x1A, 0x00, 0x01, 0x00, 0x00}));
    EXPECT_EQ(uintVal(4294967296ULL),
              bytes({0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}));
}

TEST(CborDet, NegativeInt)
{
    EXPECT_EQ(intVal(-1), bytes({0x20}));
    EXPECT_EQ(intVal(-24), bytes({0x37}));
    EXPECT_EQ(intVal(-25), bytes({0x38, 0x18}));
    EXPECT_EQ(intVal(-256), bytes({0x38, 0xFF}));
    EXPECT_EQ(intVal(-257), bytes({0x39, 0x01, 0x00}));
    // COSE alg ES384 = -35 and SHA-384 = -43.
    EXPECT_EQ(intVal(-35), bytes({0x38, 0x22}));
    EXPECT_EQ(intVal(-43), bytes({0x38, 0x2A}));
}

TEST(CborDet, TextAndBytes)
{
    EXPECT_EQ(textVal("env.gpu.0"),
              bytes({0x69, 'e', 'n', 'v', '.', 'g', 'p', 'u', '.', '0'}));
    std::vector<std::uint8_t> raw{0xDE, 0xAD};
    EXPECT_EQ(bytesVal(raw), bytes({0x42, 0xDE, 0xAD}));
}

TEST(CborDet, MapCanonicalKeyOrdering)
{
    // Insert keys out of canonical order; encode() must sort them.
    Map m;
    m.addInt(266, uintVal(1)); // 2-byte key 0x19 0x01 0x0A
    m.addInt(10, uintVal(2));  // 1-byte key 0x0A
    m.addInt(256, uintVal(3)); // 2-byte key 0x19 0x01 0x00
    m.addInt(-75000, uintVal(4));

    auto enc = m.encode();
    auto root = cbortest::decode(enc);
    ASSERT_TRUE(root->isMap());
    ASSERT_EQ(root->map.size(), 4u);

    // Canonical order: shorter encodings first, then bytewise. So 10
    // (0x0A) first, then 256 (0x19 0x01 0x00), then 266 (0x19 0x01 0x0A),
    // then -75000 (major 1, longest).
    EXPECT_EQ(root->map[0].first->ival, 10);
    EXPECT_EQ(root->map[1].first->ival, 256);
    EXPECT_EQ(root->map[2].first->ival, 266);
    EXPECT_EQ(root->map[3].first->ival, -75000);
}

TEST(CborDet, MapTextKeyOrdering)
{
    Map m;
    m.addText("vca", uintVal(1));
    m.addText("cert_chain", uintVal(2));
    m.addText("signed_measurements", uintVal(3));

    auto enc = m.encode();
    auto root = cbortest::decode(enc);
    ASSERT_TRUE(root->isMap());
    ASSERT_EQ(root->map.size(), 3u);
    // Shorter text first (cert_chain=10, vca=3 -> 'vca' is shorter so
    // actually: lengths: cert_chain=10, vca=3, signed_measurements=19.
    // Encoded key = head + utf8; head length differs: "vca" -> 0x63...,
    // "cert_chain" -> 0x6a..., "signed_measurements" -> 0x73...
    // Bytewise: 0x63 < 0x6a < 0x73, so vca, cert_chain, signed_measurements.
    EXPECT_EQ(root->map[0].first->text, "vca");
    EXPECT_EQ(root->map[1].first->text, "cert_chain");
    EXPECT_EQ(root->map[2].first->text, "signed_measurements");
}

TEST(CborDet, MapDeterministicRepeatable)
{
    Map a;
    a.addInt(3, uintVal(1));
    a.addInt(1, uintVal(2));
    a.addInt(2, uintVal(3));

    Map b;
    b.addInt(2, uintVal(3));
    b.addInt(3, uintVal(1));
    b.addInt(1, uintVal(2));

    EXPECT_EQ(a.encode(), b.encode());
}

TEST(CborDet, ArrayValue)
{
    std::vector<std::vector<std::uint8_t>> elems;
    elems.push_back(intVal(-43));
    std::vector<std::uint8_t> dig(48, 0xAB);
    elems.push_back(bytesVal(dig));
    auto enc = arrayVal(elems);

    auto root = cbortest::decode(enc);
    ASSERT_TRUE(root->isArray());
    ASSERT_EQ(root->array.size(), 2u);
    EXPECT_EQ(root->array[0]->ival, -43);
    EXPECT_TRUE(root->array[1]->isBytes());
    EXPECT_EQ(root->array[1]->bytes.size(), 48u);
}

TEST(CborDet, TagRoundTrip)
{
    std::vector<std::uint8_t> out;
    putTag(out, 602);
    putArrayHeader(out, 0);
    auto root = cbortest::decode(out);
    ASSERT_TRUE(root->isTag());
    EXPECT_EQ(root->tag, 602u);
    EXPECT_TRUE(root->tagged->isArray());
}

} // namespace
} // namespace spdmd::composite::cbor
