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

#include "composite/evidence_builder.hpp"

#include <vector>

#include <gtest/gtest.h>

namespace spdmd::composite
{
namespace
{

EvidenceBuilderInput baseSpdmInput()
{
    EvidenceBuilderInput input;
    input.environmentId = "env.gpu.0";
    input.eid = 13;
    input.success = true;
    input.spdmVersion = 0x12;
    input.measurementSpecification = kSpdmMeasurementSpecDmtf;
    input.signedMeasurements = {0x01, 0x02, 0x03};
    input.certificateChainObject = {0x30, 0x82, 0x01, 0x02};
    return input;
}

TEST(EvidenceBuilder, RefreshFailurePropagatesError)
{
    auto input = baseSpdmInput();
    input.success = false;
    input.errorMsg = "timeout";

    auto ev = buildCollectedEvidence(input);
    EXPECT_FALSE(ev.success);
    EXPECT_EQ(ev.eid, 13);
    EXPECT_EQ(ev.environmentId, "env.gpu.0");
    EXPECT_EQ(ev.errorMsg, "timeout");
}

TEST(EvidenceBuilder, SpdmEvidenceUsesRawCertificateChainObject)
{
    auto input = baseSpdmInput();
    auto ev = buildCollectedEvidence(input);

    ASSERT_TRUE(ev.success) << ev.errorMsg;
    EXPECT_EQ(ev.pattern, EvidencePattern::SpdmMeasurements);
    EXPECT_EQ(ev.signedMeasurements,
              (std::vector<std::uint8_t>{0x01, 0x02, 0x03}));
    EXPECT_EQ(ev.certChainSpdm,
              (std::vector<std::uint8_t>{0x30, 0x82, 0x01, 0x02}));
    EXPECT_FALSE(ev.includeVca);
}

TEST(EvidenceBuilder, Spdm10RequiresVcaTranscript)
{
    auto input = baseSpdmInput();
    input.spdmVersion = 0x10;

    auto ev = buildCollectedEvidence(input);
    EXPECT_FALSE(ev.success);
    EXPECT_EQ(ev.errorMsg, "missing SPDM VCA transcript");
}

TEST(EvidenceBuilder, Spdm11CopiesVcaTranscript)
{
    auto input = baseSpdmInput();
    input.spdmVersion = 0x11;
    input.vcaTranscript = {0xAA, 0xBB};

    auto ev = buildCollectedEvidence(input);
    ASSERT_TRUE(ev.success) << ev.errorMsg;
    EXPECT_TRUE(ev.includeVca);
    EXPECT_EQ(ev.vca, (std::vector<std::uint8_t>{0xAA, 0xBB}));
}

TEST(EvidenceBuilder, MissingSignedMeasurementsFails)
{
    auto input = baseSpdmInput();
    input.signedMeasurements.clear();

    auto ev = buildCollectedEvidence(input);
    EXPECT_FALSE(ev.success);
    EXPECT_EQ(ev.errorMsg, "missing SPDM signed measurements");
}

TEST(EvidenceBuilder, MissingCertificateChainObjectFails)
{
    auto input = baseSpdmInput();
    input.certificateChainObject.clear();

    auto ev = buildCollectedEvidence(input);
    EXPECT_FALSE(ev.success);
    EXPECT_EQ(ev.errorMsg, "missing SPDM certificate chain object");
}

TEST(EvidenceBuilder, EatMeasurementSpecWithTokenBuildsDeviceEatEvidence)
{
    auto input = baseSpdmInput();
    input.measurementSpecification = kSpdmMeasurementSpecEat;
    input.deviceEatToken = {0xD8, 0x3D, 0x84};

    auto ev = buildCollectedEvidence(input);
    ASSERT_TRUE(ev.success) << ev.errorMsg;
    EXPECT_EQ(ev.pattern, EvidencePattern::DeviceEat);
    EXPECT_EQ(ev.deviceTokenFormat, "application/eat+cwt");
    EXPECT_EQ(ev.deviceToken, (std::vector<std::uint8_t>{0xD8, 0x3D, 0x84}));
    EXPECT_TRUE(ev.signedMeasurements.empty());
    EXPECT_TRUE(ev.certChainSpdm.empty());
}

TEST(EvidenceBuilder, UnknownEnvironmentDetection)
{
    EXPECT_TRUE(isUnknownEnvironmentId("env.unknown.13"));
    EXPECT_FALSE(isUnknownEnvironmentId("env.gpu.0"));
}

} // namespace
} // namespace spdmd::composite
