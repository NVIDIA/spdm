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

#include <spdmcpp/endianness.hpp>

#include <array>
#include <vector>

#include <gtest/gtest.h>

using namespace spdmcpp;

// Test endianCopy for uint8_t
TEST(Endianness, EndianCopyUint8)
{
    uint8_t src = 0x42;
    uint8_t dst = 0;

    endianCopy(src, dst);
    EXPECT_EQ(dst, src);
}

// Test endianCopy for uint16_t (byte swap)
TEST(Endianness, EndianCopyUint16)
{
    uint16_t src = 0x1234;
    uint16_t dst = 0;

    endianCopy(src, dst);

    // Should be swapped: 0x3412
    EXPECT_EQ(dst, 0x3412);
}

// Test endianCopy for uint32_t (byte swap)
TEST(Endianness, EndianCopyUint32)
{
    uint32_t src = 0x12345678;
    uint32_t dst = 0;

    endianCopy(src, dst);

    // Should be swapped: 0x78563412
    EXPECT_EQ(dst, 0x78563412);
}

// Test endianHostSpdmSwap for uint8_t (no-op on little endian)
TEST(Endianness, EndianHostSpdmSwapUint8)
{
    uint8_t value = 0xAB;
    endianHostSpdmSwap(value);

    // On little endian system, should not change
    EXPECT_EQ(value, 0xAB);
}

// Test endianHostSpdmSwap for uint16_t
TEST(Endianness, EndianHostSpdmSwapUint16)
{
    uint16_t value = 0x1234;
    endianHostSpdmSwap(value);

    // On little endian, should not change
    EXPECT_EQ(value, 0x1234);
}

// Test endianHostSpdmSwap for uint32_t
TEST(Endianness, EndianHostSpdmSwapUint32)
{
    uint32_t value = 0x12345678;
    endianHostSpdmSwap(value);

    // On little endian, should not change
    EXPECT_EQ(value, 0x12345678);
}

// Test endianHostSpdmRead returns value unchanged on little endian
TEST(Endianness, EndianHostSpdmReadUint16)
{
    uint16_t value = 0xABCD;
    uint16_t result = endianHostSpdmRead(value);

    EXPECT_EQ(result, value);
}

// Test endianHostSpdmRead for uint32_t
TEST(Endianness, EndianHostSpdmReadUint32)
{
    uint32_t value = 0xDEADBEEF;
    uint32_t result = endianHostSpdmRead(value);

    EXPECT_EQ(result, value);
}

// Test endianHostSpdmCopy for uint8_t
TEST(Endianness, EndianHostSpdmCopyUint8)
{
    uint8_t src = 0xFF;
    uint8_t dst = 0;

    endianHostSpdmCopy(src, dst);
    EXPECT_EQ(dst, src);
}

// Test endianHostSpdmCopy for uint16_t
TEST(Endianness, EndianHostSpdmCopyUint16)
{
    uint16_t src = 0x1234;
    uint16_t dst = 0;

    endianHostSpdmCopy(src, dst);
    EXPECT_EQ(dst, src);
}

// Test endianHostSpdmCopy for uint32_t
TEST(Endianness, EndianHostSpdmCopyUint32)
{
    uint32_t src = 0xABCDEF01;
    uint32_t dst = 0;

    endianHostSpdmCopy(src, dst);
    EXPECT_EQ(dst, src);
}

// Test endianCopy with boundary values
TEST(Endianness, EndianCopyBoundaryValues)
{
    // Test with zero
    uint16_t zero16 = 0;
    uint16_t dst16 = 0xFFFF;
    endianCopy(zero16, dst16);
    EXPECT_EQ(dst16, 0);

    // Test with max
    uint16_t max16 = 0xFFFF;
    uint16_t dst16max = 0;
    endianCopy(max16, dst16max);
    EXPECT_EQ(dst16max, 0xFFFF); // All bits set, swap doesn't change
}

// Test endianCopy uint32 with patterns
TEST(Endianness, EndianCopyPatterns)
{
    uint32_t pattern1 = 0x00FF00FF;
    uint32_t dst1 = 0;
    endianCopy(pattern1, dst1);
    // 0x00FF00FF swapped should be 0xFF00FF00
    EXPECT_EQ(dst1, 0xFF00FF00);

    uint32_t pattern2 = 0xFF00FF00;
    uint32_t dst2 = 0;
    endianCopy(pattern2, dst2);
    // 0xFF00FF00 swapped should be 0x00FF00FF
    EXPECT_EQ(dst2, 0x00FF00FF);
}
