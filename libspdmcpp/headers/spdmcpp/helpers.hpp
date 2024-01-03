/*
 * Copyright (C) NVIDIA Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <random>
#include <span>
#include <vector>
#include <algorithm>

namespace spdmcpp
{

/** @brief helper to fill a buffer with random data
 */
inline void fillRandom(std::span<uint8_t, std::dynamic_extent> buf)
{
    std::random_device rd;
    std::default_random_engine gen(rd());
    std::uniform_int_distribution<uint8_t> distrib(0);
    std::generate(buf.begin(), buf.end(), [&]() { return distrib(gen); });
}

} // namespace spdmcpp
