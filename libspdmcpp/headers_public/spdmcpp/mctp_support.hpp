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
#include <libmctp-externals.h>

namespace spdmcpp
{
// these are for use with the mctp-demux-daemon

constexpr size_t mctpMaxMessageSize = 4096;

/** @class MctpTransportClass
 *  @brief Support class for transport through the mctp-demux-daemon
 *  @details This class should be further derived to add timeout support.
 *  Most of the interface is documented in TransportClass
 */
class MctpTransportClass : public TransportClass
{
  public:
    /** @brief The constructor
     *  @param[in] eid - The EndpointID that this instance communicates with,
     * it's checked when decoding written into the packet when encoding
     */
    explicit MctpTransportClass(uint8_t eid) : EID(eid)
    {}

    RetStat encodePre(std::vector<uint8_t>& /*buf*/, LayerState& lay) override
    {
        setLayerSize(lay, sizeof(HeaderType));
        return RetStat::OK;
    }
    RetStat encodePost(std::vector<uint8_t>& buf, LayerState& lay) override
    {
        auto& header = getHeaderRef<HeaderType>(buf, lay);
        header.mctpTag(MCTP_TAG_SPDM);
        header.eid = EID;
        header.type = MCTPMessageTypeEnum::SPDM;
        return RetStat::OK;
    }

    RetStat decode(std::vector<uint8_t>& buf, LayerState& lay) override
    {
        setLayerSize(lay, sizeof(HeaderType));
        if (!doesHeaderFit(buf, lay))
        {
            return RetStat::ERROR_BUFFER_TOO_SMALL;
        }
        const auto& header = getHeaderRef<HeaderType>(buf, lay);
        if (header.type != MCTPMessageTypeEnum::SPDM)
        {
            return RetStat::ERROR_WRONG_MCTP_TYPE;
        }
        if (header.eid != EID)
        {
            return RetStat::ERROR_WRONG_EID;
        }
        if (header.mctpTag() != MCTP_TAG_SPDM)
        {
            return RetStat::ERROR_WRONG_MCTP_TAG;
        }
        if (header.mctpTO())
        {
            return RetStat::ERROR_WRONG_MCTP_TO;
        }
        return RetStat::OK;
    }

    /** @brief Static helper for quickly fetching the EnpointID, typically for
     * routing
     *  @details The function also checks buffer bounds
     *  @param[in] buf - buffer containing the full received data
     *  @param[inout] lay - lay.Offset specifies where the transport layer
     * starts, lay.Size  will be set to the size of the transport data
     *  @param[out] eid - the EndpointID will be written to this parameter
     *  @returns OK if there were no errors and eid was written, or
     * ERROR_BUFFER_TOO_SMALL, or ERROR_WRONG_MCTP_TYPE
     */
    static RetStat peekEid(std::vector<uint8_t>& buf, LayerState& lay,
                           uint8_t& eid)
    {
        setLayerSize(lay, sizeof(HeaderType));
        if (!doesHeaderFit(buf, lay))
        {
            return RetStat::ERROR_BUFFER_TOO_SMALL;
        }
        const auto& header = getHeaderRef<HeaderType>(buf, lay);
        if (header.type != MCTPMessageTypeEnum::SPDM)
        {
            return RetStat::ERROR_WRONG_MCTP_TYPE;
        }
        if (header.mctpTag() != MCTP_TAG_SPDM)
        {
            return RetStat::ERROR_WRONG_MCTP_TAG;
        }
        if (header.mctpTO())
        {
            return RetStat::ERROR_WRONG_MCTP_TO;
        }
        eid = header.eid;
        return RetStat::OK;
    }

    /** @brief Static helper for checking if the buffer is large enough to fit
     * the header
     */
    static bool doesHeaderFit(std::vector<uint8_t>& buf, LayerState& lay)
    {
        return TransportClass::doesHeaderFit<HeaderType>(buf, lay);
    }

  protected:
    /** @brief Transport header matching the mctp-demux-daemon requirements
     */
    struct HeaderType
    {

        /** @brief MCTP header data
        */
        uint8_t mctpHeader;

        /** @brief Either source or the destination EndpointID, depending on
         * whether the packet is being sent or received. Regandless though it
         * should always
         */
        uint8_t eid;

        /** @brief Type of the message, this should always be
         * MCTPMessageTypeEnum::SPDM
         */
        MCTPMessageTypeEnum type;

        /** @brief Get The MCTP tag type
        */
        auto mctpTag() const noexcept -> mctp_tag_t
        {
            return static_cast<mctp_tag_t>(mctpHeader & 0x07);
        }

        /** @brief Set MCTP header to specific tag*/
        void mctpTag(mctp_tag_t tag) noexcept
        {
            mctpHeader = static_cast<uint8_t>(tag) | 0x08U;
        }

        /** @brieg Get MCTO TO bit
        */
        auto mctpTO() const noexcept -> bool
        {
            return mctpHeader & 0x08;
        }
    };

    /** @brief The EndpointID that this instance communicates with, it's checked
     * when decoding written into the packet when encoding
     */
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

    bool createSocket(const std::string& path)
    {
        SPDMCPP_LOG_TRACE_FUNC(Log);
        Socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
        if (Socket == -1)
        {
            return false;
        }

        // NOLINTNEXTLINE cppcoreguidelines-avoid-c-arrays
        struct sockaddr_un addr
        {};
        addr.sun_family = AF_UNIX;
        // NOLINTNEXTLINE cppcoreguidelines-pro-bounds-array-to-pointer-decay
        memcpy(addr.sun_path, path.data(), path.length());

        // NOLINTNEXTLINE cppcoreguidelines-pro-type-cstyle-cast
        if (::connect(Socket, (struct sockaddr*)&addr,
            path.length() + sizeof(addr.sun_family)) == -1)
        {
            if (Log.logLevel >= LogClass::Level::Critical)
            {
                Log.iprint("connect() error to mctp-demux-daemon, path = \"");
                Log.print(path);
                Log.print("\", errno = ");
                Log.print(errno);
                Log.print(" ");
                Log.println(std::strerror(errno));
            }
            deleteSocket();
            return false;
        }
        {
            auto type = MCTPMessageTypeEnum::SPDM;
            ssize_t ret = ::write(Socket, &type, sizeof(type));
            if (ret == -1)
            {
                if (Log.logLevel >= LogClass::Level::Critical)
                {
                    Log.iprint("Failed to write spdm code to socket, errno = ");
                    Log.print(errno);
                    Log.print(" ");
                    Log.println(strerror(errno));
                }
                deleteSocket();
                return false;
            }
        }
        if (Log.logLevel >= LogClass::Level::Informational)
        {
            Log.iprintln("AF_UNIX \\0" + path.substr(1) + ": Connection success!\n");
        }
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
            if (Log.logLevel >= LogClass::Level::Critical) {
                Log.iprint("Send error:");
                Log.println(errno);
            }
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
        if (Log.logLevel >= LogClass::Level::Critical) {
            Log.iprint("Receive error: ");
            Log.println(errno);
        }
        return RetStat::ERROR_UNKNOWN;
    }
    buf.resize(result);
    return RetStat::OK;
}

} // namespace spdmcpp
