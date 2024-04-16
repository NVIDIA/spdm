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

#include "assert.hpp"
#include "enum.hpp"
#include "flag.hpp"
#include "log.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>
#include <numeric>
#include <span>
#include <vector>

#define SPDMCPP_PACKET_HPP // this is necessary to avoid issues with clang-tidy
                           // etc being run for enum_defs.hpp

namespace spdmcpp
{
// TODO add packet constructors or some such, for safety of not forgetting to
// set some parameter?! although it may be a bit annoying to handle layering?

// TODO move most of the stuff to .cpp files

// TODO implement automatic calling of packet->finalize() for all variably sized
// packets

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SPDMCPP_LOG_expr(log, expr)                                            \
    do                                                                         \
    {                                                                          \
        (log).print(#expr ": ");                                               \
        (log).print(expr);                                                     \
    } while (false)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SPDMCPP_LOG_iexprln(log, expr)                                         \
    do                                                                         \
    {                                                                          \
        (log).iprint(#expr ":\t");                                             \
        (log).println(expr);                                                   \
    } while (false)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SPDMCPP_LOG_iflagsln(log, flags)                                       \
    do                                                                         \
    {                                                                          \
        (log).iprint(#flags ":\t");                                            \
        (log).println(get_debug_string(flags));                                \
    } while (false)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SPDMCPP_LOG_printMl(log, expr)                                         \
    do                                                                         \
    {                                                                          \
        (log).iprintln(#expr ":\t");                                           \
        (expr).printMl(log);                                                   \
    } while (false)

template <typename T, size_t N>
constexpr bool isEqual(const std::array<T, N>& array0,
                       const std::array<T, N>& array1)
{
    return std::equal(std::begin(array0), std::end(array0), std::begin(array1));
}

using nonce_array_32 = std::array<uint8_t, 32>;

struct PacketDecodeInfo
{
    uint16_t BaseHashSize = 0;
    uint16_t SignatureSize = 0;
    uint8_t ChallengeParam2 = 0;
    uint8_t GetMeasurementsParam1 = 0;
};

/*
 * Pragma pack is temporary disabled due to bug in LLVM
 * https://www.mail-archive.com/llvm-bugs@lists.llvm.org/msg69115.html
*/
#ifndef __clang__
#pragma pack(1)
#endif

#include "internal/packet_message_header.hpp"

// separator for clang-format ordering

#include "internal/packet_common.hpp"

// separator for clang-format ordering

#include "internal/packet_certificate_chain.hpp"
#include "internal/packet_measurement_block.hpp"
#include "internal/packet_measurement_field.hpp"
#include "internal/packet_version.hpp"

// separator for clang-format ordering

#include "internal/request/packet_challenge_request.hpp"
#include "internal/request/packet_get_capabilities_1_0_request.hpp"
#include "internal/request/packet_get_capabilities_request.hpp"
#include "internal/request/packet_get_certificate_request.hpp"
#include "internal/request/packet_get_digests_request.hpp"
#include "internal/request/packet_get_measurements_request.hpp"
#include "internal/request/packet_get_version_request.hpp"
#include "internal/request/packet_negotiate_algorithms_request.hpp"

// separator for lang-format ordering

#include "internal/response/packet_algorithms_response.hpp"
#include "internal/response/packet_capabilities_response.hpp"
#include "internal/response/packet_certificate_response.hpp"
#include "internal/response/packet_challenge_auth_response.hpp"
#include "internal/response/packet_digests_response.hpp"
#include "internal/response/packet_error_response.hpp"
#include "internal/response/packet_measurements_response.hpp"
#include "internal/response/packet_version_response.hpp"

/*
 * Pragma pack is temporary disabled due to bug in LLVM
 * https://www.mail-archive.com/llvm-bugs@lists.llvm.org/msg69115.html
*/
#ifndef __clang__
#pragma pack()
#endif

#undef SPDMCPP_LOG_expr
#undef SPDMCPP_LOG_iexprln
#undef SPDMCPP_LOG_iflagsln
#undef SPDMCPP_LOG_printMl
} // namespace spdmcpp

#undef SPDMCPP_PACKET_HPP
