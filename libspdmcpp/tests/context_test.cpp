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

#include <spdmcpp/context.hpp>

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace spdmcpp;

// Mock IOClass for testing
class MockIO : public IOClass
{
  public:
    MockIO() = default;
    ~MockIO() override = default;

    RetStat write(const std::vector<uint8_t>&,
                  timeout_us_t = timeoutUsInfinite) override
    {
        return RetStat::OK;
    }

    RetStat read(std::vector<uint8_t>&,
                 timeout_us_t = timeoutUsInfinite) override
    {
        return RetStat::OK;
    }
};

// Test that ContextClass initializes with supported versions
TEST(Context, InitializesWithSupportedVersions)
{
    ContextClass ctx;

    const auto& versions = ctx.getSupportedVersions();

    // Should have at least SPDM 1.0, 1.1, 1.2
    EXPECT_GE(versions.size(), 3);

    // Versions should be sorted in descending order
    for (size_t i = 1; i < versions.size(); ++i)
    {
        EXPECT_GT(versions[i - 1], versions[i]);
    }
}

// Test registerIo and getIO for in-kernel IO
TEST(Context, RegisterAndGetInKernelIO)
{
    ContextClass ctx;
    auto mockIO = std::make_shared<MockIO>();

    // Register IO
    ctx.registerIo(mockIO);

    // Get IO back
    auto retrievedIO = ctx.getIO();
    EXPECT_NE(retrievedIO, nullptr);
    EXPECT_EQ(retrievedIO, mockIO);
}

// Test unregisterIo for in-kernel IO
TEST(Context, UnregisterInKernelIO)
{
    ContextClass ctx;
    auto mockIO = std::make_shared<MockIO>();

    ctx.registerIo(mockIO);
    ctx.unregisterIo();

    // After unregister, getIO should return nullptr
    auto retrievedIO = ctx.getIO();
    EXPECT_EQ(retrievedIO, nullptr);
}

// Test registerIo with path
TEST(Context, RegisterIOWithPath)
{
    ContextClass ctx;
    auto mockIO = std::make_shared<MockIO>();
    std::string testPath = "/test/path/socket";

    // Register IO with path
    ctx.registerIo(mockIO, testPath);

    // Verify path is registered
    EXPECT_TRUE(ctx.isIOPathRegistered(testPath));

    // Get IO by path
    auto retrievedIO = ctx.getIO(testPath);
    EXPECT_EQ(retrievedIO, mockIO);
}

// Test unregisterIo with path
TEST(Context, UnregisterIOWithPath)
{
    ContextClass ctx;
    auto mockIO = std::make_shared<MockIO>();
    std::string testPath = "/test/path/socket";

    ctx.registerIo(mockIO, testPath);
    EXPECT_TRUE(ctx.isIOPathRegistered(testPath));

    // Unregister
    ctx.unregisterIo(testPath);

    // Path should no longer be registered
    EXPECT_FALSE(ctx.isIOPathRegistered(testPath));
}

// Test registering multiple IO paths
TEST(Context, RegisterMultipleIOPaths)
{
    ContextClass ctx;
    auto mockIO1 = std::make_shared<MockIO>();
    auto mockIO2 = std::make_shared<MockIO>();

    std::string path1 = "/path1";
    std::string path2 = "/path2";

    ctx.registerIo(mockIO1, path1);
    ctx.registerIo(mockIO2, path2);

    // Both paths should be registered
    EXPECT_TRUE(ctx.isIOPathRegistered(path1));
    EXPECT_TRUE(ctx.isIOPathRegistered(path2));

    // Retrieve each
    EXPECT_EQ(ctx.getIO(path1), mockIO1);
    EXPECT_EQ(ctx.getIO(path2), mockIO2);
}

// Test error when registering duplicate path
TEST(Context, ErrorOnDuplicatePath)
{
    ContextClass ctx;
    auto mockIO1 = std::make_shared<MockIO>();
    auto mockIO2 = std::make_shared<MockIO>();

    std::string path = "/duplicate/path";

    ctx.registerIo(mockIO1, path);

    // Registering same path again should throw
    EXPECT_THROW(ctx.registerIo(mockIO2, path), std::invalid_argument);
}

// Test error when unregistering non-existent path
TEST(Context, ErrorOnUnregisterNonExistentPath)
{
    ContextClass ctx;

    // Unregistering a path that was never registered should throw
    EXPECT_THROW(ctx.unregisterIo("/nonexistent"), std::invalid_argument);
}

// Test error when getting IO for non-existent path
TEST(Context, ErrorOnGetNonExistentPath)
{
    ContextClass ctx;

    // Getting IO for non-existent path should throw
    EXPECT_THROW(ctx.getIO("/nonexistent"), std::invalid_argument);
}

// Test isIOPathRegistered returns false for non-existent path
TEST(Context, IsIOPathRegisteredReturnsFalse)
{
    ContextClass ctx;

    EXPECT_FALSE(ctx.isIOPathRegistered("/never/registered"));
}
