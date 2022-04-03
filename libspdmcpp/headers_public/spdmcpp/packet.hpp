
#pragma once

#include "enum.hpp"
#include "flag.hpp"
#include "log.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>
#include <span>
#include <vector>

#define SPDMCPP_PACKET_HPP // this is necessary to avoid issues with clang-tidy
                           // etc being run for enum_defs.hpp

namespace spdmcpp
{
// TODO add packet constructors or some such, for safety of not forgetting to
// set some parameter?! although it may be a bit annoying to handle layering?
// TODO move most of the stuff to .cpp files
// TODO really could use more macros for endianHostSpdmCopy and direct_copy
// to speed up typing this out and avoid mistakes, assuming there's no pushback
// against heavy macro usage?

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SPDMCPP_LOG_expr(log, expr, ...)                                       \
    do                                                                         \
    {                                                                          \
        (log).print(#expr ": ");                                               \
        (log).print(expr __VA_OPT__(, ) __VA_ARGS__);                          \
    } while (false)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SPDMCPP_LOG_iexprln(log, expr, ...)                                    \
    do                                                                         \
    {                                                                          \
        (log).iprint(#expr ":\t");                                             \
        (log).println(expr __VA_OPT__(, ) __VA_ARGS__);                        \
    } while (false)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SPDMCPP_LOG_idataln(log, expr, ...)                                    \
    do                                                                         \
    {                                                                          \
        (log).iprint(#expr ":\t");                                             \
        (log).println((expr).data(), (expr.size())__VA_OPT__(, ) __VA_ARGS__); \
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
constexpr size_t sizeofArray(const T (&/*array*/)[N])
{
    return N;
}

template <typename T, size_t N>
constexpr size_t sizeofArray(const std::array<T, N>& /*array*/)
{
    return N;
}

template <typename T, size_t N>
constexpr bool isEqual(const T (&array0)[N], const T (&array1)[N])
{
    return std::equal(std::begin(array0), std::end(array0), std::begin(array1));
}

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
    uint16_t MeasurementHashSize = 0;
    uint16_t SignatureSize = 0;
    uint8_t ChallengeParam2 = 0;
    uint8_t GetMeasurementsParam1 = 0;
    uint8_t GetMeasurementsParam2 = 0;
};

#pragma pack(1)

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

// separator for clang-format ordering

#include "internal/response/packet_algorithms_response.hpp"
#include "internal/response/packet_capabilities_response.hpp"
#include "internal/response/packet_certificate_response.hpp"
#include "internal/response/packet_challenge_auth_response.hpp"
#include "internal/response/packet_digests_response.hpp"
#include "internal/response/packet_error_response.hpp"
#include "internal/response/packet_measurements_response.hpp"
#include "internal/response/packet_version_response.hpp"

#pragma pack()

#undef SPDMCPP_LOG_expr
#undef SPDMCPP_LOG_iexprln
#undef SPDMCPP_LOG_iflagsln
#undef SPDMCPP_LOG_printMl
} // namespace spdmcpp

#undef SPDMCPP_PACKET_HPP
