
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

inline void endianCopy(uint8_t src, uint8_t& dst)
{
    dst = src;
}
inline void endianCopy(uint16_t src, uint16_t& dst)
{
    dst = (src >> 8) | (src << 8);
}
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
template <typename T>
inline void endian_host_spdm_swap(T& value)
{
    endian_swap(value);
}
template <typename T>
inline T endian_host_spdm_read(T value)
{
    return endian_read(value);
}
template <typename T>
inline void endianHostSpdmCopy(const T& src, T& dst)
{
    endian_copy(src, dst);
}
#else
// little endian
template <typename T>
inline void endianHostSpdmSwap(T& /*value*/)
{}
template <typename T>
inline T endianHostSpdmRead(T value)
{
    return value;
}
template <typename T>
inline void endianHostSpdmCopy(const T& src, T& dst)
{
    dst = src;
}
#endif
} // namespace spdmcpp
