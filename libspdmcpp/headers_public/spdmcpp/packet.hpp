
#pragma once

#include <spdmcpp/enum.hpp>
#include <spdmcpp/flag.hpp>
#include <spdmcpp/log.hpp>

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>
#include <vector>

namespace spdmcpp
{
// TODO add packet constructors or some such, for safety of not forgetting to
// set some parameter?! although it may be a bit annoying to handle layering?
// TODO move most of the stuff to .cpp files
// TODO really could use more macros for endian_host_spdm_copy and direct_copy
// to speed up typing this out and avoid mistakes, assuming there's no pushback
// against heavy macro usage?

#define SPDMCPP_LOG_expr(log, expr, ...)                                       \
    do                                                                         \
    {                                                                          \
        (log).print(#expr ": ");                                               \
        (log).print(expr __VA_OPT__(, ) __VA_ARGS__);                          \
    } while (false)
#define SPDMCPP_LOG_iexprln(log, expr, ...)                                    \
    do                                                                         \
    {                                                                          \
        (log).iprint(#expr ":\t");                                             \
        (log).println(expr __VA_OPT__(, ) __VA_ARGS__);                        \
    } while (false)
#define SPDMCPP_LOG_idataln(log, expr, ...)                                    \
    do                                                                         \
    {                                                                          \
        (log).iprint(#expr ":\t");                                             \
        (log).println((expr).data(), (expr.size())__VA_OPT__(, ) __VA_ARGS__); \
    } while (false)
#define SPDMCPP_LOG_iflagsln(log, flags)                                       \
    do                                                                         \
    {                                                                          \
        (log).iprint(#flags ":\t");                                            \
        (log).println(get_debug_string(flags));                                \
    } while (false)
#define SPDMCPP_LOG_print_ml(log, expr)                                        \
    do                                                                         \
    {                                                                          \
        (log).iprintln(#expr ":\t");                                           \
        (expr).print_ml(log);                                                  \
    } while (false)

template <typename T, size_t N>
constexpr size_t sizeof_array(const T (&array)[N])
{
    return sizeof(array);
}

typedef uint8_t nonce_array_32[32];

struct packet_decode_info
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
#include "internal/request/packet_get_capabilities_request.hpp"
#include "internal/request/packet_get_certificate_request.hpp"
#include "internal/request/packet_get_digests_request.hpp"
#include "internal/request/packet_get_measurements_request.hpp"
#include "internal/request/packet_get_version_request.hpp"
#include "internal/request/packet_negotiate_algorithms_request.hpp"
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
#undef SPDMCPP_LOG_print_ml
} // namespace spdmcpp
