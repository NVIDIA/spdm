
#pragma once

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <ostream>

namespace spdmcpp
{
#define ENUM_START(T, UT)                                                      \
    enum class T : UT                                                          \
    {
#define ENUM_VALUE(T, N, V) N = V,
#define ENUM_END()                                                             \
    }                                                                          \
    ;

#include "enum_defs.hpp"

#undef ENUM_START
#undef ENUM_VALUE
#undef ENUM_END

#define ENUM_START(T, UT)                                                      \
    inline const char* get_cstr(T e)                                           \
    {                                                                          \
        switch (e)                                                             \
        {
#define ENUM_VALUE(T, N, V)                                                    \
    case T::N:                                                                 \
        return #T "::" #N;
#define ENUM_END()                                                             \
    }                                                                          \
    return "UNKNOWN";                                                          \
    }

#include "enum_defs.hpp"

#undef ENUM_START
#undef ENUM_VALUE
#undef ENUM_END

#define ENUM_START(T, UT)                                                      \
    inline std::ostream& operator<<(std::ostream& stream, T e)                 \
    {                                                                          \
        const char* cstr = get_cstr(e);                                        \
        stream.write(cstr, strlen(cstr));                                      \
        return stream;                                                         \
    }
#define ENUM_VALUE(T, N, V)
#define ENUM_END()

#include "enum_defs.hpp"

#undef ENUM_START
#undef ENUM_VALUE
#undef ENUM_END

constexpr inline bool is_request(RequestResponseEnum code)
{
    return code >= RequestResponseEnum::REQUEST_GET_DIGESTS &&
           code <= RequestResponseEnum::REQUEST_END_SESSION;
}
constexpr inline bool is_response(RequestResponseEnum code)
{
    return code >= RequestResponseEnum::RESPONSE_DIGESTS &&
           code <= RequestResponseEnum::RESPONSE_END_SESSION_ACK;
}

} // namespace spdmcpp
