
#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>
#include <limits>
#include <random>

// #include <array>
#include <vector>

namespace spdmcpp
{
constexpr std::mt19937::result_type mt19937DefaultSeed = 13;

inline void
    fillPseudoRandom(std::vector<uint8_t>& buf,
                     std::mt19937::result_type seed = mt19937DefaultSeed)
{
    std::mt19937 gen(seed);
    std::uniform_int_distribution<uint8_t> distrib(1); // avoid 0
    for (size_t i = 0; i < buf.size(); ++i)
    {
        buf[i] = distrib(gen);
    }
}
template <size_t N>
void fillPseudoRandom(uint8_t (&buf)[N],
                      std::mt19937::result_type seed = mt19937DefaultSeed)
{
#if 1
    std::mt19937 gen(seed);
    std::uniform_int_distribution<uint8_t> distrib(1);
    for (size_t i = 0; i < N; ++i)
    {
        buf[i] = distrib(gen);
    }
#else
    for (size_t i = 0; i < N; ++i)
    {
        buf[i] = i + 1;
    }
#endif
}

template <typename T>
inline void
    fillPseudoRandomType(T& dst,
                         std::mt19937::result_type seed = mt19937DefaultSeed)
{
    fillPseudoRandom(reinterpret_cast<uint8_t(&)[sizeof(T)]>(dst), seed);
}

template <typename T>
inline T
    returnPseudoRandomType(std::mt19937::result_type seed = mt19937DefaultSeed)
{
    T dst;
    fillPseudoRandomType(dst, seed);
    return dst;
}

inline void fillRandom(std::vector<uint8_t>& buf)
{
#if 1
    std::random_device rd;
    std::default_random_engine gen(rd());
    std::uniform_int_distribution<uint8_t> distrib(0);
    for (size_t i = 0; i < buf.size(); ++i)
    {
        buf[i] = distrib(gen);
    }
#else
    for (size_t i = 0; i < buf.size(); ++i)
    {
        buf[i] = i + 1;
    }
#endif
}

template <size_t N>
void fillRandom(uint8_t (&buf)[N])
{
#if 1
    std::random_device rd;
    std::default_random_engine gen(rd());
    std::uniform_int_distribution<uint8_t> distrib(0);
    for (size_t i = 0; i < N; ++i)
    {
        buf[i] = distrib(gen);
    }
#else
    for (size_t i = 0; i < N; ++i)
    {
        buf[i] = i + 1;
    }
#endif
}
} // namespace spdmcpp
