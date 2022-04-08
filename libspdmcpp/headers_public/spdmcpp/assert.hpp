
#pragma once

#ifndef NDEBUG
    #include <cassert>

    #define SPDMCPP_ASSERT(expr) assert((expr)) /* NOLINT cppcoreguidelines-pro-bounds-array-to-pointer-decay */
    #define SPDMCPP_STATIC_ASSERT(expr) static_assert((expr)) /* NOLINT cppcoreguidelines-pro-bounds-array-to-pointer-decay */
#else
#define SPDMCPP_ASSERT(expr)                                                   \
    do                                                                         \
    {                                                                          \
    } while (false)
#define SPDMCPP_STATIC_ASSERT(expr)                                            \
    do                                                                         \
    {                                                                          \
    } while (false)
#endif
