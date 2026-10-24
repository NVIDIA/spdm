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

// Unit tests for SubmoduleDigest — SHA-384 correctness and the
// digest-over-encoded-Claims-Set round-trip .

#include "composite/claims_set_builder.hpp"
#include "composite/submodule_digest.hpp"

#include <array>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace spdmd::composite
{
namespace
{

std::string toHex(std::span<const std::uint8_t> b)
{
    static constexpr char d[] = "0123456789abcdef";
    std::string s;
    for (auto x : b)
    {
        s.push_back(d[x >> 4]);
        s.push_back(d[x & 0xF]);
    }
    return s;
}

TEST(SubmoduleDigest, Sha384KnownVector)
{
    // SHA-384("abc") NIST test vector.
    std::vector<std::uint8_t> abc{'a', 'b', 'c'};
    auto h = sha384(abc);
    EXPECT_EQ(toHex(h),
              "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff"
              "5bed8086072ba1e7cc2358baeca134c825a7");
}

TEST(SubmoduleDigest, Sha384EmptyVector)
{
    std::vector<std::uint8_t> empty;
    auto h = sha384(empty);
    EXPECT_EQ(toHex(h),
              "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6"
              "e1da274edebfe76f65fbd51ad2f14898b95b");
}

TEST(SubmoduleDigest, RecordMatchesClaimsSetDigest)
{
    CollectedEvidence e;
    e.environmentId = "env.gpu.0";
    e.success = true;
    e.pattern = EvidencePattern::SpdmMeasurements;
    e.signedMeasurements = {0x01, 0x02, 0x03};
    e.certificateChainDer = {0x30, 0x01, 0xAA};

    auto cs = buildClaimsSet(e);
    auto rec = makeSubmoduleRecord(e.environmentId, cs);

    EXPECT_EQ(rec.environmentId, "env.gpu.0");
    EXPECT_EQ(rec.hashAlgId, kCoseAlgSha384);
    // The record digest is exactly SHA-384 over the encoded Claims-Set
    // bytes — the value a verifier recomputes.
    auto expected = sha384(cs);
    EXPECT_EQ(std::vector<std::uint8_t>(rec.digest.begin(), rec.digest.end()),
              std::vector<std::uint8_t>(expected.begin(), expected.end()));
}

TEST(SubmoduleDigest, DigestIsOverUnwrappedBytes)
{
    // Sanity: the digest is over the Claims-Set bytes, not a wrapped or
    // hex form. Two distinct Claims-Sets must produce distinct digests.
    CollectedEvidence a;
    a.success = true;
    a.signedMeasurements = {0x01};
    a.certificateChainDer = {0x30, 0x01, 0x02};
    CollectedEvidence b = a;
    b.signedMeasurements = {0x09};

    auto ra = makeSubmoduleRecord("env.a", buildClaimsSet(a));
    auto rb = makeSubmoduleRecord("env.b", buildClaimsSet(b));
    EXPECT_NE(ra.digest, rb.digest);
}

} // namespace
} // namespace spdmd::composite
