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

// Unit tests for evidence pattern selection from SPDM MeasurementSpecification.

#include "composite/types.hpp"

#include <gtest/gtest.h>

namespace spdmd::composite
{
namespace
{

TEST(EvidencePattern, DmtfMeasurementsStaySpdmEvidence)
{
    EXPECT_FALSE(hasEatMeasurementSpecification(kSpdmMeasurementSpecDmtf));
    EXPECT_EQ(selectEvidencePattern(kSpdmMeasurementSpecDmtf, false),
              EvidencePattern::SpdmMeasurements);
}

TEST(EvidencePattern, EatSpecWithoutTokenFallsBackToSpdmEvidence)
{
    EXPECT_TRUE(hasEatMeasurementSpecification(kSpdmMeasurementSpecEat));
    EXPECT_EQ(selectEvidencePattern(kSpdmMeasurementSpecEat, false),
              EvidencePattern::SpdmMeasurements);
}

TEST(EvidencePattern, EatSpecWithTokenSelectsDeviceEatEvidence)
{
    EXPECT_EQ(selectEvidencePattern(kSpdmMeasurementSpecEat, true),
              EvidencePattern::DeviceEat);
}

TEST(EvidencePattern, CombinedSpecWithTokenSelectsDeviceEatEvidence)
{
    const auto spec = static_cast<std::uint8_t>(kSpdmMeasurementSpecDmtf |
                                                kSpdmMeasurementSpecEat);
    EXPECT_EQ(selectEvidencePattern(spec, true), EvidencePattern::DeviceEat);
}

} // namespace
} // namespace spdmd::composite
