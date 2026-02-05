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

#include <spdmcpp/enum.hpp>

#include <sstream>

#include <gtest/gtest.h>

using namespace spdmcpp;

// Test isRequest helper function
TEST(Enum, IsRequestHelper)
{
    // Test request codes
    EXPECT_TRUE(isRequest(RequestResponseEnum::REQUEST_GET_DIGESTS));
    EXPECT_TRUE(isRequest(RequestResponseEnum::REQUEST_GET_CERTIFICATE));
    EXPECT_TRUE(isRequest(RequestResponseEnum::REQUEST_GET_VERSION));
    EXPECT_TRUE(isRequest(RequestResponseEnum::REQUEST_CHALLENGE));

    // Test response codes
    EXPECT_FALSE(isRequest(RequestResponseEnum::RESPONSE_DIGESTS));
    EXPECT_FALSE(isRequest(RequestResponseEnum::RESPONSE_CERTIFICATE));
    EXPECT_FALSE(isRequest(RequestResponseEnum::RESPONSE_VERSION));
}

// Test isResponse helper function
TEST(Enum, IsResponseHelper)
{
    // Test response codes
    EXPECT_TRUE(isResponse(RequestResponseEnum::RESPONSE_DIGESTS));
    EXPECT_TRUE(isResponse(RequestResponseEnum::RESPONSE_CERTIFICATE));
    EXPECT_TRUE(isResponse(RequestResponseEnum::RESPONSE_VERSION));
    EXPECT_TRUE(isResponse(RequestResponseEnum::RESPONSE_CHALLENGE_AUTH));

    // Test request codes
    EXPECT_FALSE(isResponse(RequestResponseEnum::REQUEST_GET_DIGESTS));
    EXPECT_FALSE(isResponse(RequestResponseEnum::REQUEST_GET_CERTIFICATE));
    EXPECT_FALSE(isResponse(RequestResponseEnum::REQUEST_GET_VERSION));
}

// Test get_cstr for various enums
TEST(Enum, GetCstrForHashEnum)
{
    const char* str = get_cstr(HashEnum::TPM_ALG_SHA_256);
    EXPECT_NE(str, nullptr);
    EXPECT_STREQ(str, "HashEnum::TPM_ALG_SHA_256");

    str = get_cstr(HashEnum::TPM_ALG_SHA_384);
    EXPECT_STREQ(str, "HashEnum::TPM_ALG_SHA_384");

    str = get_cstr(HashEnum::TPM_ALG_SHA_512);
    EXPECT_STREQ(str, "HashEnum::TPM_ALG_SHA_512");
}

// Test get_cstr for RetStat
TEST(Enum, GetCstrForRetStat)
{
    const char* str = get_cstr(RetStat::OK);
    EXPECT_STREQ(str, "RetStat::OK");

    str = get_cstr(RetStat::ERROR_UNKNOWN);
    EXPECT_STREQ(str, "RetStat::ERROR_UNKNOWN");

    str = get_cstr(RetStat::ERROR_BUFFER_TOO_SMALL);
    EXPECT_STREQ(str, "RetStat::ERROR_BUFFER_TOO_SMALL");
}

// Test ostream operator for enums
TEST(Enum, OstreamOperator)
{
    std::ostringstream oss;
    oss << HashEnum::TPM_ALG_SHA_256;

    EXPECT_EQ(oss.str(), "HashEnum::TPM_ALG_SHA_256");
}

// Test MessageVersionEnum values
TEST(Enum, MessageVersionEnumValues)
{
    // Verify enum values are distinct
    EXPECT_NE(MessageVersionEnum::SPDM_1_0, MessageVersionEnum::SPDM_1_1);
    EXPECT_NE(MessageVersionEnum::SPDM_1_1, MessageVersionEnum::SPDM_1_2);
    EXPECT_NE(MessageVersionEnum::SPDM_1_0, MessageVersionEnum::SPDM_1_2);
}

// Test boundary values for RequestResponseEnum
TEST(Enum, RequestResponseEnumBoundaries)
{
    // Test boundary request codes
    auto minRequest = RequestResponseEnum::REQUEST_GET_DIGESTS;
    auto maxRequest = RequestResponseEnum::REQUEST_END_SESSION;

    EXPECT_TRUE(isRequest(minRequest));
    EXPECT_TRUE(isRequest(maxRequest));

    // Test boundary response codes
    auto minResponse = RequestResponseEnum::RESPONSE_DIGESTS;
    auto maxResponse = RequestResponseEnum::RESPONSE_END_SESSION_ACK;

    EXPECT_TRUE(isResponse(minResponse));
    EXPECT_TRUE(isResponse(maxResponse));
}
