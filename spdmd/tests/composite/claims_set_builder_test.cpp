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

// Unit tests for ClaimsSetBuilder — Pattern A/C and Pattern B detached
// Claims-Sets, VCA inclusion rule, typed-value option, and error paths.

#include "cbor_test_util.hpp"
#include "composite/claims_set_builder.hpp"
#include "composite/submodule_digest.hpp"

#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace spdmd::composite
{
namespace
{

CollectedEvidence spdmDevice(bool withVca)
{
    CollectedEvidence e;
    e.environmentId = "env.gpu.0";
    e.eid = 13;
    e.success = true;
    e.pattern = EvidencePattern::SpdmMeasurements;
    e.signedMeasurements = {0x01, 0x02, 0x03, 0x04};
    e.certificateChainDer = {0x30, 0x01, 0xAA, 0x30, 0x01, 0xBB};
    if (withVca)
    {
        e.vca = {0x10, 0x20};
        e.includeVca = true;
    }
    return e;
}

CollectedEvidence eatDevice()
{
    CollectedEvidence e;
    e.environmentId = "env.nic.0";
    e.eid = 64;
    e.success = true;
    e.pattern = EvidencePattern::DeviceEat;
    e.deviceTokenFormat = "application/eat+cwt";
    e.deviceToken = {0xD2, 0x84, 0x40};
    return e;
}

std::string toHex(std::span<const std::uint8_t> bytes)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (auto byte : bytes)
    {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0x0F]);
    }
    return out;
}

TEST(ClaimsSetBuilder, SpdmPatternFieldsNoVca)
{
    auto cs = buildClaimsSet(spdmDevice(false), EvidenceCarriage::DirectMap);
    auto root = cbortest::decode(cs);
    ASSERT_TRUE(root->isMap());
    EXPECT_EQ(root->map.size(), 2u);

    auto sm = root->atText("signed_measurements");
    ASSERT_TRUE(sm && sm->isBytes());
    EXPECT_EQ(sm->bytes, (std::vector<std::uint8_t>{0x01, 0x02, 0x03, 0x04}));

    auto cc = root->atText("cert_chain");
    ASSERT_TRUE(cc && cc->isBytes());
    EXPECT_EQ(cc->bytes,
              (std::vector<std::uint8_t>{0x30, 0x01, 0xAA, 0x30, 0x01, 0xBB}));

    EXPECT_EQ(root->atText("vca"), nullptr);
}

TEST(ClaimsSetBuilder, SpdmPatternIncludesVca)
{
    auto cs = buildClaimsSet(spdmDevice(true), EvidenceCarriage::DirectMap);
    auto root = cbortest::decode(cs);
    ASSERT_TRUE(root->isMap());
    EXPECT_EQ(root->map.size(), 3u);
    auto vca = root->atText("vca");
    ASSERT_TRUE(vca && vca->isBytes());
    EXPECT_EQ(vca->bytes, (std::vector<std::uint8_t>{0x10, 0x20}));
}

TEST(ClaimsSetBuilder, DeviceEatPattern)
{
    auto cs = buildClaimsSet(eatDevice(), EvidenceCarriage::DirectMap);
    auto root = cbortest::decode(cs);
    ASSERT_TRUE(root->isMap());
    EXPECT_EQ(root->map.size(), 2u);

    auto tf = root->atText("token_format");
    ASSERT_TRUE(tf && tf->isText());
    EXPECT_EQ(tf->text, "application/eat+cwt");

    auto dt = root->atText("device_token");
    ASSERT_TRUE(dt && dt->isBytes());
    EXPECT_EQ(dt->bytes, (std::vector<std::uint8_t>{0xD2, 0x84, 0x40}));
}

TEST(ClaimsSetBuilder, DraftOcpSpdmRecordCmwVector)
{
    auto evidence = spdmDevice(false);
    evidence.signedMeasurements = {0x12, 0x01, 0x00, 0x00,
                                   0xAA, 0xBB, 0xCC, 0xDD};
    evidence.certificateChainDer = {0x30, 0x82, 0x01, 0x00,
                                    0xDE, 0xAD, 0xBE, 0xEF};

    // Draft OCP Composite EAT Profile SPDM Claims-Set vector.
    auto claimsSet = buildClaimsSet(evidence, EvidenceCarriage::RecordCmw);
    EXPECT_EQ(toHex(claimsSet),
              "a119012b83781e6170706c69636174696f6e2f7370646d2d65766964656e6365"
              "2b63626f7253824812010000aabbccdd4830820100deadbeef04");
    EXPECT_EQ(toHex(sha384(claimsSet)),
              "c322d4b38698e2a652dec5ef6c9158a1f5c654e415870d9aaccd3ae367be72bb"
              "5d5260f3433b93502a30fd858fb76746");
}

TEST(ClaimsSetBuilder, DraftOcpDeviceEatRecordCmwVector)
{
    auto evidence = eatDevice();
    evidence.deviceToken = {0xD8, 0x3D, 0xD2, 0x84, 0x40, 0xA0, 0x40, 0x40};

    // Draft OCP Composite EAT Profile device-EAT Claims-Set vector.
    auto claimsSet = buildClaimsSet(evidence, EvidenceCarriage::RecordCmw);
    EXPECT_EQ(toHex(claimsSet),
              "a119012b83736170706c69636174696f6e2f6561742b63777448d83dd28440a0"
              "404004");
    EXPECT_EQ(toHex(sha384(claimsSet)),
              "dd4e41442e3bb7b38fc05437cc9dae0b3e7a7188f37c80307f5502d5c3e38b96"
              "f88c0666707c947a352c092d58974f2c");
}

TEST(ClaimsSetBuilder, RecordCmwSpdmEvidenceIncludesVcaAsThirdPosition)
{
    auto claimsSet =
        buildClaimsSet(spdmDevice(true), EvidenceCarriage::RecordCmw);
    auto root = cbortest::decode(claimsSet);
    ASSERT_EQ(root->map.size(), 1u);
    auto cmw = root->atInt(kCwtClaimCmw);
    ASSERT_TRUE(cmw && cmw->isArray());
    ASSERT_EQ(cmw->array.size(), 3u);
    EXPECT_EQ(cmw->array[0]->text, kSpdmEvidenceMediaType);
    EXPECT_EQ(cmw->array[2]->uarg, kCmwIndicatorEvidence);
    auto spdmEvidence = cbortest::decode(cmw->array[1]->bytes);
    ASSERT_TRUE(spdmEvidence->isArray());
    ASSERT_EQ(spdmEvidence->array.size(), 3u);
    EXPECT_EQ(spdmEvidence->array[2]->bytes,
              (std::vector<std::uint8_t>{0x10, 0x20}));
}

TEST(ClaimsSetBuilder, RecordCmwRejectsUnsupportedDeviceEatMediaType)
{
    auto evidence = eatDevice();
    evidence.deviceTokenFormat = "application/eat-token";
    EXPECT_THROW(buildClaimsSet(evidence, EvidenceCarriage::RecordCmw),
                 std::invalid_argument);
}

TEST(ClaimsSetBuilder, RecordCmwRejectsEmptyRequiredEvidence)
{
    auto spdm = spdmDevice(false);
    spdm.signedMeasurements.clear();
    EXPECT_THROW(buildClaimsSet(spdm, EvidenceCarriage::RecordCmw),
                 std::invalid_argument);

    auto eat = eatDevice();
    eat.deviceToken.clear();
    EXPECT_THROW(buildClaimsSet(eat, EvidenceCarriage::RecordCmw),
                 std::invalid_argument);
}

TEST(ClaimsSetBuilder, RejectsUnknownEvidencePattern)
{
    auto evidence = spdmDevice(false);
    evidence.pattern = static_cast<EvidencePattern>(0xFF);
    EXPECT_THROW(buildClaimsSet(evidence, EvidenceCarriage::RecordCmw),
                 std::invalid_argument);
    EXPECT_THROW(buildClaimsSet(evidence, EvidenceCarriage::DirectMap),
                 std::invalid_argument);
}

TEST(ClaimsSetBuilder, RejectsUnknownEvidenceCarriage)
{
    EXPECT_THROW(
        buildClaimsSet(spdmDevice(false), static_cast<EvidenceCarriage>(0xFF)),
        std::invalid_argument);
}

TEST(ClaimsSetBuilder, Deterministic)
{
    EXPECT_EQ(buildClaimsSet(spdmDevice(true)),
              buildClaimsSet(spdmDevice(true)));
}

TEST(ClaimsSetBuilder, ThrowsOnEmptySignedMeasurements)
{
    auto e = spdmDevice(false);
    e.signedMeasurements.clear();
    EXPECT_THROW(buildClaimsSet(e), std::invalid_argument);
}

TEST(ClaimsSetBuilder, ThrowsOnEmptyCertChain)
{
    auto e = spdmDevice(false);
    e.certificateChainDer.clear();
    EXPECT_THROW(buildClaimsSet(e), std::invalid_argument);
}

TEST(ClaimsSetBuilder, ThrowsWhenVcaRequiredButEmpty)
{
    auto e = spdmDevice(false);
    e.includeVca = true;
    EXPECT_THROW(buildClaimsSet(e), std::invalid_argument);
}

TEST(ClaimsSetBuilder, ThrowsOnEmptyDeviceToken)
{
    auto e = eatDevice();
    e.deviceToken.clear();
    EXPECT_THROW(buildClaimsSet(e), std::invalid_argument);
}

} // namespace
} // namespace spdmd::composite
