
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <random>
#include <span>
#include <vector>

namespace spdmcpp
{

inline void fillRandom(std::span<uint8_t, std::dynamic_extent> buf)
{
    std::random_device rd;
    std::default_random_engine gen(rd());
    std::uniform_int_distribution<uint8_t> distrib(0);
    std::generate(buf.begin(), buf.end(), [&]() { return distrib(gen); });
}

} // namespace spdmcpp
