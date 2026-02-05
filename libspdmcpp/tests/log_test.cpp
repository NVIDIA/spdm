/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDM-License-Identifier: Apache-2.0
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

#include <spdmcpp/common.hpp>
#include <spdmcpp/enum.hpp>
#include <spdmcpp/log.hpp>

#include <array>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <vector>

#include <gtest/gtest.h>

using namespace spdmcpp;

// Test LogClass construction and log level
TEST(Log, ConstructionAndLogLevel)
{
    std::ostringstream oss;
    LogClass log(oss);

    // Default log level should be Emergency
    EXPECT_EQ(log.logLevel, LogClass::Level::Emergency);
}

// Test LogClass construction with custom log level
TEST(Log, ConstructionWithCustomLogLevel)
{
    std::ostringstream oss;
    LogClass log(oss, LogClass::Level::Debug);

    EXPECT_EQ(log.logLevel, LogClass::Level::Debug);
}

// Test setLogLevel
TEST(Log, SetLogLevel)
{
    std::ostringstream oss;
    LogClass log(oss);

    log.setLogLevel(LogClass::Level::Warning);
    EXPECT_EQ(log.logLevel, LogClass::Level::Warning);

    log.setLogLevel(LogClass::Level::Informational);
    EXPECT_EQ(log.logLevel, LogClass::Level::Informational);
}

// Test basic print functionality
TEST(Log, BasicPrint)
{
    std::ostringstream oss;
    LogClass log(oss);

    log.print("Hello");
    EXPECT_EQ(oss.str(), "Hello");
}

// Test println functionality
TEST(Log, Println)
{
    std::ostringstream oss;
    LogClass log(oss);

    log.println("Test message");
    EXPECT_EQ(oss.str(), "Test message\n");
}

// Test printing multiple values
TEST(Log, PrintMultipleValues)
{
    std::ostringstream oss;
    LogClass log(oss);

    log.print("Value: ", 42, " End");
    EXPECT_EQ(oss.str(), "Value: 42 End");
}

// Test printing different integer types
TEST(Log, PrintIntegerTypes)
{
    std::ostringstream oss;
    LogClass log(oss);

    uint8_t u8 = 255;
    uint16_t u16 = 1000;
    uint32_t u32 = 50000;

    log.print(u8);
    log.print(" ");
    log.print(u16);
    log.print(" ");
    log.print(u32);

    EXPECT_EQ(oss.str(), "255 1000 50000");
}

// Test printing vectors
TEST(Log, PrintVector)
{
    std::ostringstream oss;
    LogClass log(oss);

    std::vector<uint8_t> vec = {0x01, 0x02, 0xFF};
    log.print(vec);

    // Should print as hex values
    std::string output = oss.str();
    EXPECT_FALSE(output.empty());
}

// Test indentation
TEST(Log, IndentationBasic)
{
    std::ostringstream oss;
    LogClass log(oss);

    log.println("Before");
    log.indent();
    log.iprintln("Indented");
    log.unindent();
    log.println("After");

    std::string output = oss.str();
    // Indented line should have a tab character
    EXPECT_NE(output.find('\t'), std::string::npos);
}

// Test multiple indentation levels
TEST(Log, MultipleIndentLevels)
{
    std::ostringstream oss;
    LogClass log(oss);

    log.iprintln("Level 0");
    log.indent();
    log.iprintln("Level 1");
    log.indent();
    log.iprintln("Level 2");
    log.unindent();
    log.iprintln("Level 1 again");
    log.unindent();
    log.iprintln("Level 0 again");

    std::string output = oss.str();
    // Should have different indentation levels
    EXPECT_FALSE(output.empty());
}

// Test IndentHelper RAII
TEST(Log, IndentHelperRAII)
{
    std::ostringstream oss;
    LogClass log(oss);

    log.iprintln("Before block");
    {
        IndentHelper helper(log);
        log.iprintln("Inside block");
    }
    log.iprintln("After block");

    std::string output = oss.str();
    EXPECT_FALSE(output.empty());
}

// Test unindent on already at zero level
TEST(Log, UnindentAtZero)
{
    std::ostringstream oss;
    LogClass log(oss);

    // Should not crash when unindenting at level 0
    log.unindent();
    log.print("Still works");

    EXPECT_EQ(oss.str(), "Still works");
}

// Test printing string types
TEST(Log, PrintStringTypes)
{
    std::ostringstream oss;
    LogClass log(oss);

    std::string str = "std::string";
    const char* cstr = "const char*";
    char arr[] = "char array";

    log.print(str);
    log.print(" ");
    log.print(cstr);
    log.print(" ");
    log.print(arr);

    EXPECT_EQ(oss.str(), "std::string const char* char array");
}

// Cover print(chrono::time_point) from gcov report
TEST(Log, PrintChronoTimePoint)
{
    std::ostringstream oss;
    LogClass log(oss);
    auto tp = std::chrono::system_clock::now();
    log.print(tp);
    std::string out = oss.str();
    EXPECT_FALSE(out.empty());
    EXPECT_NE(out.find('.'), std::string::npos);
}

// Cover print<T> for enums (uses get_cstr) and get_cstr(RetStat,
// MessageVersionEnum, RequestResponseEnum, AlgTypeEnum)
TEST(Log, PrintEnumTypes)
{
    std::ostringstream oss;
    LogClass log(oss, LogClass::Level::Informational);
    log.print(RetStat::OK);
    EXPECT_FALSE(oss.str().empty());
    oss.str("");
    log.print(MessageVersionEnum::SPDM_1_0);
    EXPECT_FALSE(oss.str().empty());
    oss.str("");
    log.print(RequestResponseEnum::REQUEST_GET_VERSION);
    EXPECT_FALSE(oss.str().empty());
    oss.str("");
    log.print(AlgTypeEnum::DHE);
    EXPECT_FALSE(oss.str().empty());
}

// Cover println overloads: string, unsigned long, uint8_t, etc.
TEST(Log, PrintlnOverloads)
{
    std::ostringstream oss;
    LogClass log(oss);
    log.println(std::string("str"));
    EXPECT_EQ(oss.str(), "str\n");
    oss.str("");
    log.println(42UL);
    EXPECT_EQ(oss.str(), "42\n");
    oss.str("");
    log.println(static_cast<uint8_t>(1));
    EXPECT_EQ(oss.str(), "1\n");
    oss.str("");
    log.println(1u);
    EXPECT_EQ(oss.str(), "1\n");
    oss.str("");
    log.println(static_cast<unsigned short>(2));
    EXPECT_EQ(oss.str(), "2\n");
}

// Cover TraceHelper (SPDMCPP_LOG_TRACE_FUNC / SPDMCPP_LOG_TRACE_BLOCK)
TEST(Log, TraceHelper)
{
    std::ostringstream oss;
    LogClass log(oss, LogClass::Level::Debug);
    SPDMCPP_LOG_TRACE_FUNC(log);
    EXPECT_FALSE(oss.str().empty());
    oss.str("");
    SPDMCPP_LOG_TRACE_BLOCK(log);
    EXPECT_FALSE(oss.str().empty());
}

// Cover iprint with string and unsigned long (indent level 0 => no tab)
TEST(Log, IprintStringAndULong)
{
    std::ostringstream oss;
    LogClass log(oss);
    log.iprint(std::string("indented"));
    EXPECT_EQ(oss.str(), "indented");
    oss.str("");
    log.iprint(99UL);
    EXPECT_EQ(oss.str(), "99");
}

// Cover iprintln with string and unsigned long (indent level 0 => no tab)
TEST(Log, IprintlnStringAndULong)
{
    std::ostringstream oss;
    LogClass log(oss);
    log.iprintln(std::string("line"));
    EXPECT_EQ(oss.str(), "line\n");
    oss.str("");
    log.iprintln(100UL);
    EXPECT_EQ(oss.str(), "100\n");
}

// Cover remaining println overloads (gcov: char, const char*, enums, array,
// unsigned types)
TEST(Log, PrintlnRemainingOverloads)
{
    std::ostringstream oss;
    LogClass log(oss);
    log.println(static_cast<char>('x'));
    EXPECT_EQ(oss.str(), "x\n");
    oss.str("");
    log.println("const char*");
    EXPECT_EQ(oss.str(), "const char*\n");
    oss.str("");
    log.println(MessageVersionEnum::SPDM_1_1);
    EXPECT_FALSE(oss.str().empty());
    oss.str("");
    log.println(RequestResponseEnum::RESPONSE_VERSION);
    EXPECT_FALSE(oss.str().empty());
    oss.str("");
    std::array<uint8_t, 32> arr32{};
    arr32.fill(0xAB);
    log.println(arr32);
    EXPECT_FALSE(oss.str().empty());
    oss.str("");
    std::array<uint8_t, 3> arr3 = {0x01, 0x02, 0x03};
    log.println(arr3);
    EXPECT_FALSE(oss.str().empty());
    oss.str("");
    log.println(static_cast<unsigned char>(5));
    EXPECT_EQ(oss.str(), "5\n");
    oss.str("");
    log.println(100u);
    EXPECT_EQ(oss.str(), "100\n");
    oss.str("");
    log.println(200UL);
    EXPECT_EQ(oss.str(), "200\n");
    oss.str("");
    log.println(static_cast<unsigned short>(10));
    EXPECT_EQ(oss.str(), "10\n");
}
