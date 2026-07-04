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

#include <stdexcept>
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
    e.certChainSpdm = {0xAA, 0xBB, 0xCC};
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

TEST(ClaimsSetBuilder, SpdmPatternFieldsNoVca)
{
    auto cs = buildClaimsSet(spdmDevice(false));
    auto root = cbortest::decode(cs);
    ASSERT_TRUE(root->isMap());
    EXPECT_EQ(root->map.size(), 2u);

    auto sm = root->atText("signed_measurements");
    ASSERT_TRUE(sm && sm->isBytes());
    EXPECT_EQ(sm->bytes, (std::vector<std::uint8_t>{0x01, 0x02, 0x03, 0x04}));

    auto cc = root->atText("cert_chain");
    ASSERT_TRUE(cc && cc->isBytes());
    EXPECT_EQ(cc->bytes, (std::vector<std::uint8_t>{0xAA, 0xBB, 0xCC}));

    EXPECT_EQ(root->atText("vca"), nullptr);
}

TEST(ClaimsSetBuilder, SpdmPatternIncludesVca)
{
    auto cs = buildClaimsSet(spdmDevice(true));
    auto root = cbortest::decode(cs);
    ASSERT_TRUE(root->isMap());
    EXPECT_EQ(root->map.size(), 3u);
    auto vca = root->atText("vca");
    ASSERT_TRUE(vca && vca->isBytes());
    EXPECT_EQ(vca->bytes, (std::vector<std::uint8_t>{0x10, 0x20}));
}

TEST(ClaimsSetBuilder, DeviceEatPattern)
{
    auto cs = buildClaimsSet(eatDevice());
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

TEST(ClaimsSetBuilder, TypedValuesWrapSpdmFields)
{
    auto cs = buildClaimsSet(spdmDevice(false), /*typedValues=*/true);
    auto root = cbortest::decode(cs);
    auto sm = root->atText("signed_measurements");
    ASSERT_TRUE(sm && sm->isArray());
    ASSERT_EQ(sm->array.size(), 2u);
    EXPECT_TRUE(sm->array[0]->isUint());
    EXPECT_EQ(sm->array[0]->uarg, kCfSpdmMeasurements);
    EXPECT_TRUE(sm->array[1]->isBytes());
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
    e.certChainSpdm.clear();
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
