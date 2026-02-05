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

#include <spdmcpp/flag.hpp>

#include <sstream>

#include <gtest/gtest.h>

using namespace spdmcpp;

// Test countBits for various flag values
TEST(Flag, CountBitsSingleFlag)
{
    // Single bit set
    EXPECT_EQ(countBits(BaseHashAlgoFlags::TPM_ALG_SHA_256), 1);
    EXPECT_EQ(countBits(BaseHashAlgoFlags::TPM_ALG_SHA_384), 1);
    EXPECT_EQ(countBits(BaseHashAlgoFlags::TPM_ALG_SHA_512), 1);
}

// Test countBits for combined flags
TEST(Flag, CountBitsMultipleFlags)
{
    auto combined =
        BaseHashAlgoFlags::TPM_ALG_SHA_256 | BaseHashAlgoFlags::TPM_ALG_SHA_384;
    EXPECT_EQ(countBits(combined), 2);

    auto triple = BaseHashAlgoFlags::TPM_ALG_SHA_256 |
                  BaseHashAlgoFlags::TPM_ALG_SHA_384 |
                  BaseHashAlgoFlags::TPM_ALG_SHA_512;
    EXPECT_EQ(countBits(triple), 3);
}

// Test countBits for zero (no flags set)
TEST(Flag, CountBitsZero)
{
    BaseHashAlgoFlags none = static_cast<BaseHashAlgoFlags>(0);
    EXPECT_EQ(countBits(none), 0);
}

// Test flag OR operator
TEST(Flag, OrOperator)
{
    auto flag1 = BaseHashAlgoFlags::TPM_ALG_SHA_256;
    auto flag2 = BaseHashAlgoFlags::TPM_ALG_SHA_384;

    auto combined = flag1 | flag2;

    // Combined should have both bits set
    EXPECT_EQ(countBits(combined), 2);
    EXPECT_TRUE((combined & flag1) == flag1);
    EXPECT_TRUE((combined & flag2) == flag2);
}

// Test flag AND operator
TEST(Flag, AndOperator)
{
    auto combined =
        BaseHashAlgoFlags::TPM_ALG_SHA_256 | BaseHashAlgoFlags::TPM_ALG_SHA_384;

    auto result1 = combined & BaseHashAlgoFlags::TPM_ALG_SHA_256;
    EXPECT_EQ(result1, BaseHashAlgoFlags::TPM_ALG_SHA_256);

    auto result2 = combined & BaseHashAlgoFlags::TPM_ALG_SHA_512;
    EXPECT_EQ(result2, static_cast<BaseHashAlgoFlags>(0));
}

// Test flag OR-assignment operator
TEST(Flag, OrAssignmentOperator)
{
    auto flags = BaseHashAlgoFlags::TPM_ALG_SHA_256;
    flags |= BaseHashAlgoFlags::TPM_ALG_SHA_384;

    EXPECT_EQ(countBits(flags), 2);
}

// Test flag AND-assignment operator
TEST(Flag, AndAssignmentOperator)
{
    auto flags =
        BaseHashAlgoFlags::TPM_ALG_SHA_256 | BaseHashAlgoFlags::TPM_ALG_SHA_384;

    flags &= BaseHashAlgoFlags::TPM_ALG_SHA_256;

    EXPECT_EQ(flags, BaseHashAlgoFlags::TPM_ALG_SHA_256);
    EXPECT_EQ(countBits(flags), 1);
}

// Test flag negation operator
TEST(Flag, NegationOperator)
{
    BaseHashAlgoFlags none = static_cast<BaseHashAlgoFlags>(0);
    BaseHashAlgoFlags some = BaseHashAlgoFlags::TPM_ALG_SHA_256;

    EXPECT_TRUE(!none);
    EXPECT_FALSE(!some);
}

// Test toStringHex for different sizes
TEST(Flag, ToStringHexFormats)
{
    uint8_t v8 = 0xFF;
    uint16_t v16 = 0x1234;
    uint32_t v32 = 0xABCD0000;

    // Test that toStringHex produces valid hex strings
    std::string str8 = toStringHex(v8);
    std::string str16 = toStringHex(v16);
    std::string str32 = toStringHex(v32);

    // Should start with "0x"
    EXPECT_EQ(str8.substr(0, 2), "0x");
    EXPECT_EQ(str16.substr(0, 2), "0x");
    EXPECT_EQ(str32.substr(0, 2), "0x");

    // Should have correct padding (2 hex digits per byte)
    EXPECT_GE(str8.length(), 4);   // "0x" + 2 digits
    EXPECT_GE(str16.length(), 6);  // "0x" + 4 digits
    EXPECT_GE(str32.length(), 10); // "0x" + 8 digits
}

// Test get_string for flags
TEST(Flag, GetStringForFlags)
{
    auto single = BaseHashAlgoFlags::TPM_ALG_SHA_256;
    std::string str = get_string(single);

    // Should contain flag name
    EXPECT_FALSE(str.empty());
    EXPECT_NE(str.find("TPM_ALG_SHA_256"), std::string::npos);
}

// Test get_string for combined flags
TEST(Flag, GetStringForCombinedFlags)
{
    auto combined =
        BaseHashAlgoFlags::TPM_ALG_SHA_256 | BaseHashAlgoFlags::TPM_ALG_SHA_384;

    std::string str = get_string(combined);

    // Should contain both flag names
    EXPECT_NE(str.find("TPM_ALG_SHA_256"), std::string::npos);
    EXPECT_NE(str.find("TPM_ALG_SHA_384"), std::string::npos);
    EXPECT_NE(str.find("|"), std::string::npos);
}

// Test capability flags operations
TEST(Flag, CapabilityFlagsOperations)
{
    auto cert = RequesterCapabilitiesFlags::CERT_CAP;
    auto chal = RequesterCapabilitiesFlags::CHAL_CAP;
    auto meas = RequesterCapabilitiesFlags::MEAS_CAP_01;

    auto combined = cert | chal | meas;

    EXPECT_EQ(countBits(combined), 3);
    EXPECT_TRUE((combined & cert) == cert);
    EXPECT_TRUE((combined & chal) == chal);
    EXPECT_TRUE((combined & meas) == meas);
}

// Test getHashSize for BaseHashAlgoFlags
TEST(Flag, GetHashSizeBaseHashAlgo)
{
    EXPECT_GT(getHashSize(BaseHashAlgoFlags::TPM_ALG_SHA_256), 0);
    EXPECT_GT(getHashSize(BaseHashAlgoFlags::TPM_ALG_SHA_384), 0);
    EXPECT_GT(getHashSize(BaseHashAlgoFlags::TPM_ALG_SHA_512), 0);
}

// Test getHashSize for MeasurementHashAlgoFlags
TEST(Flag, GetHashSizeMeasurementHashAlgo)
{
    EXPECT_GT(getHashSize(MeasurementHashAlgoFlags::TPM_ALG_SHA_256), 0);
    EXPECT_GT(getHashSize(MeasurementHashAlgoFlags::TPM_ALG_SHA_384), 0);
    EXPECT_GT(getHashSize(MeasurementHashAlgoFlags::TPM_ALG_SHA_512), 0);
}

// Test getSignatureSize for BaseAsymAlgoFlags
TEST(Flag, GetSignatureSizeBaseAsymAlgo)
{
    EXPECT_GT(getSignatureSize(BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P256),
              0);
    EXPECT_GT(getSignatureSize(BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P384),
              0);
    EXPECT_GT(getSignatureSize(BaseAsymAlgoFlags::TPM_ALG_RSASSA_2048), 0);
}

// Cover toStringHex<uint32_t> and get_debug_string (gcov report)
TEST(Flag, ToStringHexUint32)
{
    std::string s = toStringHex(0x1234u);
    EXPECT_FALSE(s.empty());
    EXPECT_EQ(s.substr(0, 2), "0x");
    s = toStringHex(static_cast<uint32_t>(0xabcd));
    EXPECT_NE(s.find("abcd"), std::string::npos);
}

// Cover get_debug_string for flag types (gcov report)
TEST(Flag, GetDebugString)
{
    std::string s = get_debug_string(BaseHashAlgoFlags::TPM_ALG_SHA_256);
    EXPECT_FALSE(s.empty());
    EXPECT_NE(s.find("TPM_ALG_SHA_256"), std::string::npos);
    s = get_debug_string(ResponderCapabilitiesFlags::CERT_CAP);
    EXPECT_FALSE(s.empty());
    s = get_debug_string(RequesterCapabilitiesFlags::CERT_CAP);
    EXPECT_FALSE(s.empty());
    s = get_debug_string(BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P256);
    EXPECT_FALSE(s.empty());
    s = get_debug_string(MeasurementHashAlgoFlags::TPM_ALG_SHA_256);
    EXPECT_FALSE(s.empty());
}
