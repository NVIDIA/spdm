/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
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





#pragma once

#include "enum.hpp"
#include "flag.hpp"
#include "retstat.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <ostream>
#include <vector>

namespace spdmcpp
{
///
/// SPDM packet endianness helpers
///

/** @brief function copies src to dst and always does a byte-swap
 *  @details This is just for consistency so that it's always safe to call
 * endianCopy or endianHostSpdm* functions
 */
inline void endianCopy(uint8_t src, uint8_t& dst)
{
    dst = src;
}

/** @brief function copies src to dst and always does a byte-swap
 */
inline void endianCopy(uint16_t src, uint16_t& dst)
{
    dst = (src >> 8) | (src << 8);
}

/** @brief function copies src to dst and always does a byte-swap
 */
inline void endianCopy(uint32_t src, uint32_t& dst)
{
    src = ((src >> 8) & 0x00FF00FF) | ((src << 8) & 0xFF00FF00);
    dst = (src >> 16) | (src << 16);
}

// TODO proper macro check!!! with override for testing? or just have always
// swapping functions? and alias/stub for each type?!
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SPDMCPP_BIG_ENDIAN 0

#if SPDMCPP_BIG_ENDIAN
// big endian

/** @brief function byte-swaps the value (if necessary) between spdm and host
 * endianness
 *  @details big endian variant, byte-swaps
 *  @param[inout] value - value to endian swap
 */
template <typename T>
inline void endian_host_spdm_swap(T& value)
{
    endian_swap(value);
}

/** @brief function returns a byte-swaped (if necessary) value between spdm and
 * host endianness
 *  @details big endian variant, byte-swaps
 *  @param[in] value - input value
 *  @returns - byte-swapped value
 */
template <typename T>
inline T endian_host_spdm_read(T value)
{
    return endian_read(value);
}

/** @brief function copies a value with byte-swapping (if necessary) between
 * spdm and host endianness
 *  @details big endian variant, byte-swaps
 *  @param[in] src - input value
 *  @param[out] dst - output byte-swapped value
 */
template <typename T>
inline void endianHostSpdmCopy(const T& src, T& dst)
{
    endian_copy(src, dst);
}
#else
// little endian

/** @brief function byte-swaps the value (if necessary) between spdm and host
 * endianness
 *  @details little endian variant, doesn't byte-swap
 *  @param[inout] value - value to endian swap
 */
template <typename T>
inline void endianHostSpdmSwap(T& /*value*/)
{}

/** @brief function returns a byte-swaped (if necessary) value between spdm and
 * host endianness
 *  @details little endian variant, doesn't byte-swap
 *  @param[in] value - input value
 *  @returns - byte-swapped value
 */
template <typename T>
inline T endianHostSpdmRead(T value)
{
    return value;
}

/** @brief function copies a value with byte-swapping (if necessary) between
 * spdm and host endianness
 *  @details little endian variant, doesn't byte-swap
 *  @param[in] src - input value
 *  @param[out] dst - output byte-swapped value
 */
template <typename T>
inline void endianHostSpdmCopy(const T& src, T& dst)
{
    dst = src;
}

#endif
} // namespace spdmcpp
