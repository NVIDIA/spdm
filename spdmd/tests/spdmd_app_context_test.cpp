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

#include "spdmd_app_context.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

// Global static variables for our mocks
static int mock_enabled = 0;
static uint64_t mock_usec = 0;
static std::vector<std::string> notify_calls;

// Helper functions for tests
void mock_watchdog_enabled(bool enabled, uint64_t timeout_usec = 30000000)
{
    mock_enabled = enabled ? 1 : 0;
    mock_usec = timeout_usec;
}

std::vector<std::string>& get_sd_notify_calls()
{
    return notify_calls;
}

void reset_sd_notify_calls()
{
    notify_calls.clear();
}

// Mock for systemd functions
extern "C"
{
    int sd_watchdog_enabled(int unset_environment, uint64_t* usec)
    {
        (void)unset_environment; // Avoid unused parameter warning

        if (mock_enabled)
        {
            *usec = mock_usec;
        }

        return mock_enabled;
    }

    int sd_notify(int unset_environment, const char* state)
    {
        (void)unset_environment; // Avoid unused parameter warning

        // Record calls
        notify_calls.push_back(state);
        return 0;
    }
}

namespace spdmd
{

class SpdmdAppContextTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        reset_sd_notify_calls();
    }

    void TearDown() override
    {
        // Reset mocks
        mock_watchdog_enabled(false);
    }

    std::stringstream logStream;
};

// Test for when watchdog is disabled
TEST_F(SpdmdAppContextTest, NoWatchdogWhenDisabled)
{
    // Configure mock to indicate watchdog is disabled
    mock_watchdog_enabled(false);

    // Create the object under test
    SpdmdAppContext appContext(logStream);

    // Call the method being tested
    appContext.connectDBus("test.watchdog.disabled");

    // Run IO loop briefly to check if anything happens
    auto& io = appContext.getIo();
    boost::asio::steady_timer shortTimer(io, std::chrono::milliseconds(10));
    shortTimer.async_wait(
        [&io](const boost::system::error_code&) { io.stop(); });
    io.run();

    // There should be no sd_notify calls
    EXPECT_TRUE(get_sd_notify_calls().empty());
}

// Test for when watchdog is enabled
TEST_F(SpdmdAppContextTest, WatchdogWhenEnabled)
{
    // Configure mock to indicate watchdog is enabled with a very short timeout
    // Use much shorter timeout for testing (1000 microseconds = 1ms)
    mock_watchdog_enabled(true, 1000);

    // Create the object under test
    SpdmdAppContext appContext(logStream);

    // Call the method being tested
    appContext.connectDBus("test.watchdog.enabled");

    // Run IO loop for longer to ensure the watchdog timer fires
    auto& io = appContext.getIo();
    boost::asio::steady_timer shortTimer(io, std::chrono::milliseconds(500));
    shortTimer.async_wait(
        [&io](const boost::system::error_code&) { io.stop(); });
    io.run();

    // There should be at least one sd_notify call with "WATCHDOG=1"
    auto& calls = get_sd_notify_calls();

    // Add debug output if the test fails
    if (calls.empty())
    {
        std::cout
            << "DEBUG: No watchdog notifications received. Timer might not have fired."
            << std::endl;
    }

    ASSERT_FALSE(calls.empty())
        << "Expected at least one watchdog notification";
    EXPECT_EQ("WATCHDOG=1", calls[0]);
}

// Test for when watchdog has zero timeout
TEST_F(SpdmdAppContextTest, NoWatchdogWhenZeroTimeout)
{
    // Configure mock to indicate watchdog is enabled but with zero timeout
    mock_watchdog_enabled(true, 0);

    // Create the object under test
    SpdmdAppContext appContext(logStream);

    // Call the method being tested
    appContext.connectDBus("test.watchdog.zero");

    // Run IO loop briefly
    auto& io = appContext.getIo();
    boost::asio::steady_timer shortTimer(io, std::chrono::milliseconds(10));
    shortTimer.async_wait(
        [&io](const boost::system::error_code&) { io.stop(); });
    io.run();

    // There should be no sd_notify calls
    EXPECT_TRUE(get_sd_notify_calls().empty());
}

} // namespace spdmd