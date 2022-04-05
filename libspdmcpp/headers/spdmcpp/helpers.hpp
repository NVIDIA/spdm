
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <random>
#include <vector>

namespace spdmcpp
{

inline void fillRandom(uint8_t* buf, size_t len)
{
    std::random_device rd;
    std::default_random_engine gen(rd());
    std::uniform_int_distribution<uint8_t> distrib(0);
    for (size_t i = 0; i < len; ++i)
    {
        buf[i] = distrib(gen);
    }
}

inline void fillRandom(std::vector<uint8_t>& buf)
{
    return fillRandom(buf.data(), buf.size());
}

template <size_t N>
void fillRandom(std::array<uint8_t, N>& buf)
{
    fillRandom(buf.data(), buf.size());
}

template <size_t N>
void fillRandom(uint8_t (&buf)[N])
{
    return fillRandom(buf, N);
}

} // namespace spdmcpp
