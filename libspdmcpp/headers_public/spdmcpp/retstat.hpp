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

#include "enum.hpp"

#include <cstdint>
#include <cstring>
#include <limits>

namespace spdmcpp
{
inline bool isError(RetStat value)
{
    if (static_cast<std::underlying_type_t<RetStat>>(value) < 0)
    {
        return true;
    }
    return false;
}

// TODO code -> error description string!
/*	inline const char* get_description_cstr(RetStat rs)
    {
        switch(rs) {
            case RetStat::OK:
                return "RetStat::OK";
            case RetStat::WARNING_BUFFER_TOO_BIG:
                return "RetStat::WARNING_BUFFER_TOO_BIG";
            case RetStat::ERROR_UNKNOWN:
                return "RetStat::ERROR_UNKNOWN";
            case RetStat::ERROR_BUFFER_TOO_SMALL:
                return "RetStat::ERROR_BUFFER_TOO_SMALL";
            case RetStat::ERROR_WRONG_REQUEST_RESPONSE_CODE:
                return "RetStat::ERROR_WRONG_REQUEST_RESPONSE_CODE";
            default:
                return "RetStat::INVALID";
        }
    }*/

// TODO do we want different layers/types of codes to avoid checking for errors
// that don't make sense for a function and other such issues?! we could also
// have helpers to change from one to another in cases where it's sensible

} // namespace spdmcpp
