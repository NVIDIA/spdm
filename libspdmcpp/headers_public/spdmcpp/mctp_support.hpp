
#pragma once

#include "assert.hpp"
#include "common.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>
#include <vector>

namespace spdmcpp
{
// these are for use with the mctp-demux-daemon

constexpr size_t mctpMaxMessageSize = 4096;

/** @class MctpTransportClass
 *  @brief Support class for transport through the mctp-demux-daemon
 *  @details This class should be further derived to add timeout support
 */
class MctpTransportClass : public TransportClass
{
  public:
    explicit MctpTransportClass(uint8_t eid) : EID(eid)
    {}

    void setEid(uint8_t eid)
    {
        SPDMCPP_ASSERT(EID == 0);
        EID = eid;
    }

    RetStat encodePre(std::vector<uint8_t>& /*buf*/, LayerState& lay) override
    {
        setLayerSize(lay, sizeof(HeaderType));
        return RetStat::OK;
    }
    RetStat encodePost(std::vector<uint8_t>& buf, LayerState& lay) override
    {
        auto& header = getHeaderRef<HeaderType>(buf, lay);
        header.eid = EID;
        header.type = MCTPMessageTypeEnum::SPDM;
        return RetStat::OK;
    }

    RetStat decode(std::vector<uint8_t>& buf, LayerState& lay) override
    {
        setLayerSize(lay, sizeof(HeaderType));
        const auto& header = getHeaderRef<HeaderType>(buf, lay);
        if (header.type != MCTPMessageTypeEnum::SPDM)
        {
            return RetStat::ERROR_UNKNOWN;
        }
        return RetStat::OK;
    }

    static RetStat peekEid(std::vector<uint8_t>& buf, LayerState& lay,
                           uint8_t& eid)
    {
        setLayerSize(lay, sizeof(HeaderType));
        const auto& header = getHeaderRef<HeaderType>(buf, lay);
        if (header.type != MCTPMessageTypeEnum::SPDM)
        {
            return RetStat::ERROR_UNKNOWN;
        }
        eid = header.eid;
        return RetStat::OK;
    }

  protected:
    struct HeaderType
    {
        uint8_t eid;
        MCTPMessageTypeEnum type;
    };

    uint8_t EID = 0;
};

// NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class MctpIoClass : public IOClass
{
  public:
    explicit MctpIoClass(LogClass& log) : Log(log)
    {}

    ~MctpIoClass() override
    {
        if (isSocketOpen())
        {
            deleteSocket();
        }
    }

    bool createSocket()
    {
        SPDMCPP_LOG_TRACE_FUNC(Log);
        Socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
        if (Socket == -1)
        {
            return false;
        }

        // NOLINTNEXTLINE cppcoreguidelines-avoid-c-arrays
        const char path[] = "\0mctp-mux";
        struct sockaddr_un addr
        {};
        addr.sun_family = AF_UNIX;
        // NOLINTNEXTLINE cppcoreguidelines-pro-bounds-array-to-pointer-decay
        memcpy(addr.sun_path, path, sizeof(path) - 1);

        // NOLINTNEXTLINE cppcoreguidelines-pro-type-cstyle-cast
        if (::connect(Socket, (struct sockaddr*)&addr,
                      sizeof(path) + sizeof(addr.sun_family) - 1) == -1)
        {
            Log.iprint("connect() error to mctp-demux-daemon, errno = ");
            Log.print(errno);
            Log.print(" ");
            Log.println(std::strerror(errno));
            deleteSocket();
            return false;
        }
        {
            auto type = MCTPMessageTypeEnum::SPDM;
            ssize_t ret = ::write(Socket, &type, sizeof(type));
            if (ret == -1)
            {
                Log.iprint("Failed to write spdm code to socket, errno = ");
                Log.print(errno);
                Log.print(" ");
                Log.println(strerror(errno));
                deleteSocket();
                return false;
            }
        }
        Log.iprintln("Connection success!\n");
        return true;
    }
    void deleteSocket()
    {
        close(Socket);
        Socket = -1;
    }

    RetStat write(const std::vector<uint8_t>& buf,
                  timeout_us_t timeout = timeoutUsInfinite) override;
    RetStat read(std::vector<uint8_t>& buf,
                 timeout_us_t timeout = timeoutUsInfinite) override;

    int isSocketOpen() const
    {
        return Socket != -1;
    }
    int getSocket() const
    {
        return Socket;
    }

  private:
    LogClass& Log;
    int Socket = -1;
};

inline RetStat MctpIoClass::write(const std::vector<uint8_t>& buf,
                                  timeout_us_t /*timeout*/)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    size_t sent = 0;
    while (sent < buf.size())
    {
        ssize_t ret = send(Socket, (void*)&buf[sent], buf.size() - sent, 0);
        if (ret == -1)
        {
            Log.iprint("Send error:");
            Log.println(errno);
            return RetStat::ERROR_UNKNOWN;
        }
        sent += ret;
    }
    return RetStat::OK;
}

inline RetStat MctpIoClass::read(std::vector<uint8_t>& buf,
                                 timeout_us_t /*timeout*/)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    buf.resize(mctpMaxMessageSize);
    ssize_t result = recv(Socket, (void*)buf.data(), buf.size(), 0);
    if (result == -1 || result == 0)
    {
        buf.clear();
        Log.iprint("Receive error:");
        Log.println(errno);
        return RetStat::ERROR_UNKNOWN;
    }
    buf.resize(result);
    return RetStat::OK;
}

} // namespace spdmcpp
