
#pragma once

#include "log.hpp"
#include "packet.hpp"
#include "retstat.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>
#include <span>
#include <vector>

namespace spdmcpp
{
using timeout_us_t = uint64_t; /// in units of 1 micro second
enum : timeout_us_t
{
    TIMEOUT_US_INFINITE = std::numeric_limits<timeout_us_t>::max(),
    TIMEOUT_US_MAXIMUM = TIMEOUT_US_INFINITE - 1
};

using timeout_ms_t = uint64_t; /// in units of 1 milli second
enum : timeout_ms_t
{
    TIMEOUT_MS_INFINITE = std::numeric_limits<timeout_ms_t>::max(),
    TIMEOUT_MS_MAXIMUM = TIMEOUT_MS_INFINITE - 1
};

class ConnectionClass;
class ContextClass;

/** @struct NonCopyable
 *  @brief Helper class for deleting copy ops
 *  @details We often don't needed/want these and clang-tidy complains about
 * them
 */
struct NonCopyable
{
    NonCopyable() = default;
    ~NonCopyable() = default;

    NonCopyable(const NonCopyable& other) = delete;
    NonCopyable& operator=(const NonCopyable&) = delete;

    NonCopyable(NonCopyable&&) = delete;
    NonCopyable& operator=(NonCopyable&&) = delete;
};

// NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class TransportClass : public NonCopyable
{
  public:
    class LayerState
    {
        friend TransportClass;

      public:
        size_t getOffset() const
        {
            return Offset;
        }
        size_t getEndOffset() const
        {
            return Offset + Size;
        }

      protected:
        size_t Offset = 0;
        size_t Size = 0;
    };

    virtual ~TransportClass() = default;

    virtual RetStat encodePre(std::vector<uint8_t>& buf, LayerState& lay) = 0;
    virtual RetStat encodePost(std::vector<uint8_t>& buf, LayerState& lay) = 0;

    virtual RetStat decode(std::vector<uint8_t>& buf, LayerState& lay) = 0;

    virtual RetStat setupTimeout(timeout_ms_t /*timeout*/)
    {
        return RetStat::ERROR_UNKNOWN;
    }
    virtual bool clearTimeout()
    {
        return false;
    }

  protected:
    template <class T>
    static T& getHeaderRef(std::vector<uint8_t>& buf, LayerState& lay)
    {
        // NOLINTNEXTLINE cppcoreguidelines-pro-type-reinterpret-cast
        return *reinterpret_cast<T*>(&buf[lay.getOffset()]);
    }

    static void setLayerOffset(LayerState& lay, size_t v)
    {
        lay.Offset = v;
    }
    static void setLayerSize(LayerState& lay, size_t v)
    {
        lay.Size = v;
    }
};

// NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class IOClass : NonCopyable
{
  public:
    virtual ~IOClass() = default;
    virtual RetStat write(const std::vector<uint8_t>& buf,
                          timeout_us_t timeout = TIMEOUT_US_INFINITE) = 0;
    virtual RetStat read(std::vector<uint8_t>& buf,
                         timeout_us_t timeout = TIMEOUT_US_INFINITE) = 0;
    virtual RetStat setupTimeout(timeout_us_t /*timeout*/)
    {
        return RetStat::ERROR_UNKNOWN;
    }
};

} // namespace spdmcpp

// #include "connection.hpp"
// #include "context.hpp"
