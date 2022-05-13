
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
