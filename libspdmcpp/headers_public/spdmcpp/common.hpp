
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
constexpr timeout_us_t timeoutUsInfinite =
    std::numeric_limits<timeout_us_t>::max();
constexpr timeout_us_t timeoutUsMaximum = timeoutUsInfinite - 1;

using timeout_ms_t = uint64_t; /// in units of 1 milli second
constexpr timeout_ms_t timeoutMsInfinite =
    std::numeric_limits<timeout_ms_t>::max();
constexpr timeout_ms_t timeoutMsMaximum = timeoutMsInfinite - 1;

/**
 * @enum transportMedium
 * @brief Specify transport medium under MCTP protocol
*/
enum class TransportMedium : char {
    PCIe,
    SPI,
    I2C
};

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

/** @class TransportClass
 *  @brief Abstract interface for wrapping spdm messages with a certain
 * transport protocol and handling timeouts
 *  @details The various abstract methods are called by ConnectionClass to
 * encode/decode messages and setup asynchronuous timeouts
 */
// NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class TransportClass : public NonCopyable
{
  public:
    /** @class LayerState
     *  @brief Helper for layouting layers in a buffer
     */
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

    /** @brief function called by ConnectionClass before encoding an spdm
     * message into a buffer
     *  @details it must write the size of the transport data into lay.Size,
     * besides that it can already write it's data into buf at lay.getOffset()
     *           afterwards the spdm message will be written at
     * buf[lay.getEndOffset()]
     *  @param[out] buf - buffer into which data can be written
     *  @param[inout] lay - lay.Offset specifies where the transport layer
     * starts, lay.Size should be set to the size of the transport data
     */
    virtual RetStat encodePre(std::vector<uint8_t>& buf, LayerState& lay) = 0;

    /** @brief function called by ConnectionClass after encoding an spdm message
     * into a buffer
     *  @details it can finish any work necessary to construct the transport
     * data, the spdm message is already entirely written into buf, starting at
     * lay.getEndOffset() until buf.size()
     *  @param[out] buf - buffer into which data can be written
     *  @param[in] lay - specifies the location and extent of the transport
     * layer data inside buf
     */
    virtual RetStat encodePost(std::vector<uint8_t>& buf, LayerState& lay) = 0;

    /** @brief function called by ConnectionClass when decoding a received spdm
     * message
     *  @details it should analyze the transport data which starts at
     * buf[lay.getOffset] for correctness and set lay.Size appropriately
     * (lay.getEndOffset() must indicate where the spdm message begins)
     *  @param[in] buf - buffer containing the full received data
     *  @param[inout] lay - lay.Offset specifies where the transport layer
     * starts, lay.Size should be set to the size of the transport data
     */
    virtual RetStat decode(std::vector<uint8_t>& buf, LayerState& lay) = 0;

    /** @brief function called by ConnectionClass to setup a timeout
     *  @details after the provided time has passed without receiving any
     * message (calling ConnectionClass::handle_recv()), the given
     * implementation is expected to call ConnectionClass::handle_timeout()
     *  @param[out] buf - buffer into which data can be written
     */
    virtual RetStat setupTimeout(timeout_ms_t /*timeout*/)
    {
        return RetStat::ERROR_UNKNOWN;
    }

    /** @brief function called by ConnectionClass to clear a previously set
     * timeout
     *  @returns true if the timeout was setup and cleared, false if the timeout
     * was not previously setup
     */
    virtual bool clearTimeout()
    {
        return false;
    }

  protected:
    /** @brief function to help with writing simple statically sized headers
     * into buf
     */
    template <class T>
    static T& getHeaderRef(std::vector<uint8_t>& buf, LayerState& lay)
    {
        // NOLINTNEXTLINE cppcoreguidelines-pro-type-reinterpret-cast
        return *reinterpret_cast<T*>(&buf[lay.getOffset()]);
    }

    /** @brief helper for checking if the buffer is large enough
     */
    template <class T>
    static bool doesHeaderFit(std::vector<uint8_t>& buf, LayerState& lay)
    {
        return lay.getOffset() + sizeof(T) <= buf.size();
    }

    /** @brief helper for setting layer value
     */
    static void setLayerOffset(LayerState& lay, size_t v)
    {
        lay.Offset = v;
    }
    /** @brief helper for setting layer value
     */
    static void setLayerSize(LayerState& lay, size_t v)
    {
        lay.Size = v;
    }
};

/** @class IOClass
 *  @brief Abstract interface for writing/reading full transport+spdm packets
 * to/from some I/O medium, typically a socket, or buffers during unit-tests
 *  @details write will be called by ConnectionClass when it sends a packet,
 * read will be called by the application and the buffer provided to
 * ConnectionClass through handleRecv()
 */
// NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class IOClass : NonCopyable
{
  public:
    virtual ~IOClass() = default;

    /** @brief function called by ConnectionClass when it has encoded a full
     * transport+spdm packet and wishes to send it
     *  @param[in] buf - buffer containing the data to be sent
     */
    virtual RetStat write(const std::vector<uint8_t>& buf,
                          timeout_us_t timeout = timeoutUsInfinite) = 0;

    /** @brief function called by the application either synchronuously or after
     * receiving an event
     *  @param[out] buf - buffer into which the full packet data must be written
     */
    virtual RetStat read(std::vector<uint8_t>& buf,
                         timeout_us_t timeout = timeoutUsInfinite) = 0;
};

} // namespace spdmcpp
