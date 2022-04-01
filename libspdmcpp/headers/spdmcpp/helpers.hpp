
#pragma once

#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <limits>
#include <random>
#include <vector>

namespace spdmcpp
{
constexpr std::mt19937::result_type mt19937DefaultSeed = 13;

inline void
    fillPseudoRandom(uint8_t* buf, size_t len,
                     std::mt19937::result_type seed = mt19937DefaultSeed)
{
    std::mt19937 gen(seed);
    std::uniform_int_distribution<uint8_t> distrib(1);
    for (size_t i = 0; i < len; ++i)
    {
        buf[i] = distrib(gen);
    }
}

inline void
    fillPseudoRandom(std::vector<uint8_t>& buf,
                     std::mt19937::result_type seed = mt19937DefaultSeed)
{
    fillPseudoRandom(buf.data(), buf.size(), seed);
}

template <size_t N>
void fillPseudoRandom(std::array<uint8_t, N>& buf,
                      std::mt19937::result_type seed = mt19937DefaultSeed)
{
    fillPseudoRandom(buf.data(), buf.size(), seed);
}

template <size_t N>
void fillPseudoRandom(uint8_t (&buf)[N],
                      std::mt19937::result_type seed = mt19937DefaultSeed)
{
    fillPseudoRandom(buf, N, seed);
}

template <typename T>
inline void
    fillPseudoRandomType(T& dst,
                         std::mt19937::result_type seed = mt19937DefaultSeed)
{
    fillPseudoRandom(reinterpret_cast<uint8_t*>(&dst), sizeof(dst), seed);
}

template <typename T>
inline T
    returnPseudoRandomType(std::mt19937::result_type seed = mt19937DefaultSeed)
{
    T dst;
    fillPseudoRandomType(dst, seed);
    return dst;
}

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
