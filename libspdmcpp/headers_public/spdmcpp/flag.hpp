
#pragma once

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <limits>
#include <ostream>
#include <sstream>

#define SPDMCPP_FLAG_HPP // this is necessary to avoid issues with clang-tidy
                         // etc being run for flag_defs.hpp

namespace spdmcpp
{
template <typename T>
size_t countBits(T value)
{
    size_t ret = 0;
    for (size_t i = 0; i < sizeof(T) * 8; ++i)
    {
        ret += value & 1;
        value >>= 1;
        if (!value)
        {
            break;
        }
    }
    return ret;
}

template <typename T>
std::string to_string_hex(T v)
{
    std::ostringstream stream;
    stream << "0x" << std::setfill('0') << std::setw(sizeof(T) * 2) << std::hex
           << v;
    return stream.str();
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define FLAG_START(T, UT)                                                      \
    enum class T : UT                                                          \
    {
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define FLAG_VALUE(T, N, V) N = (V),
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define FLAG_END(T, UT)                                                        \
    }                                                                          \
    ;                                                                          \
    inline T operator|(T lhs, T rhs)                                           \
    {                                                                          \
        return static_cast<T>(static_cast<UT>(lhs) | static_cast<UT>(rhs));    \
    }                                                                          \
    inline T operator&(T lhs, T rhs)                                           \
    {                                                                          \
        return static_cast<T>(static_cast<UT>(lhs) & static_cast<UT>(rhs));    \
    }                                                                          \
    inline T operator|=(T& lhs, T rhs)                                         \
    {                                                                          \
        return lhs = lhs | rhs;                                                \
    }                                                                          \
    inline T operator&=(T& lhs, T rhs)                                         \
    {                                                                          \
        return lhs = lhs & rhs;                                                \
    }                                                                          \
    inline bool operator!(T flags)                                             \
    {                                                                          \
        return flags == static_cast<T>(0);                                     \
    }

#include "flag_defs.hpp"

#undef FLAG_START
#undef FLAG_VALUE
#undef FLAG_END

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define FLAG_START(T, UT)                                                      \
    inline std::string get_string(T flags)                                     \
    {                                                                          \
        std::string ret = "(";                                                 \
        bool first = true;
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define FLAG_VALUE(T, N, V)                                                    \
    if (!!T::N && (flags & T::N) == T::N)                                      \
    {                                                                          \
        if (!first)                                                            \
            ret += " | ";                                                      \
        ret += #T "::" #N;                                                     \
        first = false;                                                         \
    }
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define FLAG_END(T, UT)                                                        \
    return ret + ")";                                                          \
    }

#include "flag_defs.hpp"

#undef FLAG_START
#undef FLAG_VALUE
#undef FLAG_END

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define FLAG_START(T, UT)                                                      \
    inline std::string get_debug_string(T flags)                               \
    {                                                                          \
        std::string ret = "(" + to_string_hex(static_cast<UT>(flags)) + " ";   \
        bool first = true;
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define FLAG_VALUE(T, N, V)                                                    \
    if (!!T::N && (flags & T::N) == T::N)                                      \
    {                                                                          \
        if (!first)                                                            \
            ret += " | ";                                                      \
        ret += #T "::" #N;                                                     \
        first = false;                                                         \
    }
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define FLAG_END(T, UT)                                                        \
    return ret + ")";                                                          \
    }

#include "flag_defs.hpp"

#undef FLAG_START
#undef FLAG_VALUE
#undef FLAG_END

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define FLAG_START(T, UT)                                                      \
    inline std::ostream& operator<<(std::ostream& stream, T e)                 \
    {                                                                          \
        std::string str = get_debug_string(e);                                 \
        stream.write(str.data(), str.size());                                  \
        return stream;                                                         \
    }
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define FLAG_VALUE(T, N, V)
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define FLAG_END(T, UT)

#include "flag_defs.hpp"

#undef FLAG_START
#undef FLAG_VALUE
#undef FLAG_END

inline uint16_t getHashSize(BaseHashAlgoFlags flags)
{
    assert(countBits(static_cast<std::underlying_type_t<BaseHashAlgoFlags>>(
               flags)) <= 1);
    switch (flags)
    {
        case BaseHashAlgoFlags::TPM_ALG_SHA_256:
            return 32;
        case BaseHashAlgoFlags::TPM_ALG_SHA_384:
            return 48;
        case BaseHashAlgoFlags::TPM_ALG_SHA_512:
            return 64;
        case BaseHashAlgoFlags::TPM_ALG_SHA3_256:
            return 32;
        case BaseHashAlgoFlags::TPM_ALG_SHA3_384:
            return 48;
        case BaseHashAlgoFlags::TPM_ALG_SHA3_512:
            return 64;
        default:
            return 0;
    }
}

inline uint16_t getHashSize(MeasurementHashAlgoFlags flags)
{
    assert(
        countBits(static_cast<std::underlying_type_t<MeasurementHashAlgoFlags>>(
            flags)) <= 1);
    switch (flags)
    {
        case MeasurementHashAlgoFlags::RAW_BIT_STREAM_ONLY:
            return 0;
        case MeasurementHashAlgoFlags::TPM_ALG_SHA_256:
            return 32;
        case MeasurementHashAlgoFlags::TPM_ALG_SHA_384:
            return 48;
        case MeasurementHashAlgoFlags::TPM_ALG_SHA_512:
            return 64;
        case MeasurementHashAlgoFlags::TPM_ALG_SHA3_256:
            return 32;
        case MeasurementHashAlgoFlags::TPM_ALG_SHA3_384:
            return 48;
        case MeasurementHashAlgoFlags::TPM_ALG_SHA3_512:
            return 64;
        default:
            return 0;
    }
}

inline uint16_t getSignatureSize(BaseAsymAlgoFlags flags)
{
    assert(countBits(static_cast<std::underlying_type_t<BaseAsymAlgoFlags>>(
               flags)) <= 1);
    switch (flags)
    {
        case BaseAsymAlgoFlags::TPM_ALG_RSASSA_2048:
            return 256;
        case BaseAsymAlgoFlags::TPM_ALG_RSAPSS_2048:
            return 256;
        case BaseAsymAlgoFlags::TPM_ALG_RSASSA_3072:
            return 384;
        case BaseAsymAlgoFlags::TPM_ALG_RSAPSS_3072:
            return 384;
        case BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P256:
            return 64;
        case BaseAsymAlgoFlags::TPM_ALG_RSASSA_4096:
            return 512;
        case BaseAsymAlgoFlags::TPM_ALG_RSAPSS_4096:
            return 512;
        case BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P384:
            return 96;
        case BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P521:
            return 132;
        default:
            return 0;
    }
}

} // namespace spdmcpp

#undef SPDMCPP_FLAG_HPP
