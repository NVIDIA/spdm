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

#include "config.h"

#include "test_helpers.hpp"

#include <spdmcpp/common.hpp>
#include <spdmcpp/retstat.hpp>

#include <gtest/gtest.h>

using namespace spdmcpp;

class RetstatTest : public ::testing::Test
{};

TEST_F(RetstatTest, IsErrorReturnsFalseForOk)
{
    EXPECT_FALSE(isError(RetStat::OK));
}

TEST_F(RetstatTest, IsErrorReturnsTrueForErrorUnknown)
{
    EXPECT_TRUE(isError(RetStat::ERROR_UNKNOWN));
}

TEST_F(RetstatTest, IsErrorReturnsTrueForErrorBufferTooSmall)
{
    EXPECT_TRUE(isError(RetStat::ERROR_BUFFER_TOO_SMALL));
}

TEST_F(RetstatTest, IsErrorReturnsTrueForErrorWrongRequestResponseCode)
{
    EXPECT_TRUE(isError(RetStat::ERROR_WRONG_REQUEST_RESPONSE_CODE));
}

TEST_F(RetstatTest, IsErrorReturnsFalseForWarningBufferTooBig)
{
    EXPECT_FALSE(isError(RetStat::WARNING_BUFFER_TOO_BIG));
}
