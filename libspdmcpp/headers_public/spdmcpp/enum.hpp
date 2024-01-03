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

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <ostream>

#define SPDMCPP_ENUM_HPP // this is necessary to avoid issues with clang-tidy
                         // etc being run for enum_defs.hpp

namespace spdmcpp
{

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ENUM_START(T, UT)                                                      \
    enum class T : UT                                                          \
    {
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ENUM_VALUE(T, N, V) N = (V),
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ENUM_END()                                                             \
    }                                                                          \
    ;

#include "enum_defs.hpp"

#undef ENUM_START
#undef ENUM_VALUE
#undef ENUM_END

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ENUM_START(T, UT)                                                      \
    inline const char* get_cstr(T e)                                           \
    {                                                                          \
        switch (e)                                                             \
        {
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ENUM_VALUE(T, N, V)                                                    \
    case T::N:                                                                 \
        return #T "::" #N;
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ENUM_END()                                                             \
    }                                                                          \
    return "UNKNOWN";                                                          \
    }

#include "enum_defs.hpp"

#undef ENUM_START
#undef ENUM_VALUE
#undef ENUM_END

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ENUM_START(T, UT)                                                      \
    inline std::ostream& operator<<(std::ostream& stream, T e)                 \
    {                                                                          \
        const char* cstr = get_cstr(e);                                        \
        stream.write(cstr, strlen(cstr));                                      \
        return stream;                                                         \
    }
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ENUM_VALUE(T, N, V)
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ENUM_END()

#include "enum_defs.hpp"

#undef ENUM_START
#undef ENUM_VALUE
#undef ENUM_END

/** @brief helper to identify request codes
 *  @param[in] code - spdm message code
 *  @returns true if the code corresponds to a request, false otherwise
 */
constexpr inline bool isRequest(RequestResponseEnum code)
{
    return code >= RequestResponseEnum::REQUEST_GET_DIGESTS &&
           code <= RequestResponseEnum::REQUEST_END_SESSION;
}

/** @brief helper to identify response codes
 *  @param[in] code - spdm message code
 *  @returns true if the code corresponds to a response, false otherwise
 */
constexpr inline bool isResponse(RequestResponseEnum code)
{
    return code >= RequestResponseEnum::RESPONSE_DIGESTS &&
           code <= RequestResponseEnum::RESPONSE_END_SESSION_ACK;
}

} // namespace spdmcpp

#undef SPDMCPP_ENUM_HPP
