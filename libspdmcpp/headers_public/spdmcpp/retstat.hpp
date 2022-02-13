
#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>
#include <limits>

// #include <array>
// #include <vector>

namespace spdmcpp
{
enum class RetStat : int32_t
{
    OK = 0,
    WARNING_BUFFER_TOO_BIG =
        1, // TODO some of these may be better as flags?! but then we must use
           // helper functions or better make it a simple class?
    ERROR_UNKNOWN = -1,
    ERROR_BUFFER_TOO_SMALL = -2,
    ERROR_WRONG_REQUEST_RESPONSE_CODE = -3,
};

inline bool is_error(RetStat value)
{
    if (static_cast<int32_t>(value) < 0) // TODO underlying_type is too new?
        return true;
    return false;
}

// TODO code -> error description string!
inline const char* get_cstr(RetStat rs)
{
    switch (rs)
    {
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
    }
    return "RetStat::INVALID";
}

// TODO do we want different layers/types of codes to avoid checking for errors
// that don't make sense for a function and other such issues?! we could also
// have helpers to change from one to another in cases where it's sensible

enum class EventRetStat : int32_t
{
    OK = 0,
    ERROR_EXIT = -1,
};

} // namespace spdmcpp
