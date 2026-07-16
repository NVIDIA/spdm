/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
#include <linux/if_arp.h>
#include <linux/mctp.h>
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

// MCTP tag type and constants (avoiding dependency on libmctp-externals.h)
// Note: MCTP_TAG_OWNER is already defined in <linux/mctp.h>
using mctp_tag_t = uint8_t;
constexpr mctp_tag_t MCTP_TAG_SPDM = 1;

#define MCTP_TYPE_SPDM 5
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
    // Bound for AF_MCTP sendto() blocking time. If the kernel TX queue stays
    // full longer than this, write() returns ERROR_TRANSPORT_BUSY and the
    // SPDM timeout/retry mechanism retransmits.
    static constexpr int mctpSendTimeoutSecs = 5;

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

    /**
     * @brief Creates a socket for MCTP communication in in-kernel mode.
     *
     * This function creates a socket using the MCTP protocol and binds it to
     * a specified address. If the socket creation or binding fails, it logs
     * the error and returns false.
     *
     * @return true if the socket is successfully created and bound, false
     * otherwise.
     */

    bool createSocket()
    {
        SPDMCPP_LOG_TRACE_FUNC(Log);

        // NOLINTNEXTLINE cppcoreguidelines-avoid-c-arrays
        struct sockaddr_mctp addr;

        Socket = socket(AF_MCTP, SOCK_DGRAM, 0);
        if (Socket < 0)
        {
            Log.iprint("socket() error: ");
            Log.println(errno);
            return false;
        }

        // Bound how long sendto() may block when the kernel MCTP TX queue is
        // saturated. Without this a full queue blocks the boost::asio
        // io_context thread indefinitely and risks a watchdog kill.
        // SO_SNDTIMEO causes sendto() to return EAGAIN after 5 s; write()
        // maps that to RetStat::ERROR_TRANSPORT_BUSY so the SPDM retry
        // mechanism can recover without blocking the event loop.
        {
            struct timeval tv = {mctpSendTimeoutSecs, 0};
            if (setsockopt(Socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) !=
                0)
            {
                Log.iprint("setsockopt(SO_SNDTIMEO) failed: ");
                Log.println(errno);
                deleteSocket();
                return false;
            }
        }

        // NOLINTNEXTLINE cppcoreguidelines-pro-bounds-array-to-pointer-decay
        memset(&addr, 0, sizeof(addr));
        addr.smctp_family = AF_MCTP;
        addr.smctp_network = MCTP_NET_ANY;
        addr.smctp_addr.s_addr = MCTP_ADDR_ANY;
        addr.smctp_type = MCTP_TYPE_SPDM;
        addr.smctp_tag = MCTP_TAG_OWNER;

        int rc = bind(Socket, (struct sockaddr*)&addr, sizeof(addr));
        // NOLINTNEXTLINE cppcoreguidelines-pro-type-cstyle-cast
        if (rc)
        {
            if (Log.logLevel >= LogClass::Level::Critical)
            {
                Log.iprint("bind to socket failed");
            }
            deleteSocket();
            return false;
        }
        else
        {
            if (Log.logLevel >= spdmcpp::LogClass::Level::Informational)
            {
                Log.iprint("Binding success\n");
            }
        }
        return true;
    }

    /**
     * @brief Creates a UNIX domain socket and connects to the specified path.
     *
     * This function creates a UNIX domain socket and attempts to connect it to
     * the specified path. If the socket creation or connection fails, it logs
     * the error and returns false. If the connection is successful, it writes
     * a message type to the socket.
     *
     * @param path The path to connect the UNIX domain socket to.
     * @return true if the socket is successfully created and connected, false
     * otherwise.
     */
    bool createSocket(const std::string& path)
    {
        SPDMCPP_LOG_TRACE_FUNC(Log);
        Socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
        if (Socket == -1)
        {
            Log.iprint("socket() error: ");
            Log.println(errno);
            return false;
        }

        // NOLINTNEXTLINE cppcoreguidelines-avoid-c-arrays
        struct sockaddr_un addr{};
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
            Log.iprintln("AF_UNIX \\0" + path.substr(1) +
                         ": Connection success!\n");
        }
        return true;
    }
    /**
     * @brief Closes the socket and resets the socket descriptor.
     *
     * This function closes the socket if it is open and resets the socket
     * descriptor to -1.
     */
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

#ifdef MCTP_IN_KERNEL
/**
 * @brief Sends data over the MCTP socket.
 *
 * This function sends the provided buffer over the MCTP socket to a specified
 * address. It constructs the destination address using the MCTP protocol and
 * sends the data using the `sendto` function. If an error occurs during
 * sending, it logs the error and returns an error status.
 *
 * @param buf The buffer containing the data to be sent.
 * @param timeout The timeout value for the operation (not used in this
 * implementation).
 * @return RetStat::OK if the data is sent successfully, RetStat::ERROR_UNKNOWN
 * otherwise.
 */
inline RetStat MctpIoClass::write(const std::vector<uint8_t>& buf,
                                  [[maybe_unused]] timeout_us_t /*timeout*/)
{
    if (buf.size() < 3)
    {
        if (Log.logLevel >= LogClass::Level::Critical)
        {
            Log.iprint("Send error: invalid MCTP frame size");
        }
        return RetStat::ERROR_BUFFER_TOO_SMALL;
    }

    struct sockaddr_mctp addr;
    memset(&addr, 0, sizeof(addr));

    addr.smctp_family = AF_MCTP;
    addr.smctp_network = MCTP_NET_ANY;
    addr.smctp_addr.s_addr = buf[1];
    addr.smctp_tag = MCTP_TAG_OWNER;
    addr.smctp_type = MCTP_TYPE_SPDM;

    ssize_t rc =
        sendto(Socket, buf.data() + 3, buf.size() - 3, 0,
               reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    if (rc == -1)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            // SO_SNDTIMEO expired — TX queue still full after 5 s.
            // Return a transient error so the caller can drop the send
            // and let the SPDM timeout/retry path recover, without
            // treating this as a hard transport failure.
            if (Log.logLevel >= LogClass::Level::Warning)
            {
                Log.iprint(
                    "AF_MCTP TX queue full (EAGAIN), dropping SPDM send; "
                    "retry via SPDM timeout");
                Log.println(errno);
            }
            return RetStat::ERROR_TRANSPORT_BUSY;
        }
        if (Log.logLevel >= LogClass::Level::Critical)
        {
            Log.iprint("Send error:");
            Log.println(errno);
        }
        return RetStat::ERROR_UNKNOWN;
    }
    return RetStat::OK;
}

/**
 * @brief Reads data from the MCTP socket.
 *
 * This function reads data from the MCTP socket into the provided buffer. It
 * first peeks the buffer length to determine the size of the incoming message,
 * then resizes the buffer accordingly and reads the data. The function also
 * constructs a header with specific MCTP address and message type information
 * and prepends it to the buffer. If an error occurs during the read operation,
 * it logs the error and returns an error status.
 *
 * @param buf The buffer to store the received data.
 * @param timeout The timeout value for the operation (not used in this
 * implementation).
 * @return RetStat::OK if the data is read successfully, RetStat::ERROR_UNKNOWN
 * otherwise.
 */
inline RetStat MctpIoClass::read(std::vector<uint8_t>& buf,
                                 [[maybe_unused]] timeout_us_t /*timeout*/)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    struct sockaddr_mctp addr;
    socklen_t addrlen = sizeof(addr);

    memset(&addr, 0, sizeof(addr));

    ssize_t bufLen = recv(Socket, NULL, 0, MSG_PEEK | MSG_TRUNC);
    if (bufLen < 0)
    {
        Log.iprint("Error peeking buffer length: ");
        Log.println(errno);
        return RetStat::ERROR_UNKNOWN;
    }
    buf.resize(bufLen);
    ssize_t ret = recvfrom(Socket, buf.data(), buf.size(), MSG_TRUNC,
                           (struct sockaddr*)&addr, &addrlen);
    std::vector<int> head = {1, addr.smctp_addr.s_addr,
                             static_cast<int>(MCTPMessageTypeEnum::SPDM)};

    buf.insert(buf.begin(), head.begin(), head.end());

    if (ret == -1)
    {
        if (Log.logLevel >= LogClass::Level::Critical)
        {
            Log.iprint("Receive error: ");
            Log.println(errno);
        }
        return RetStat::ERROR_UNKNOWN;
    }
    return RetStat::OK;
}

#else

/**
 * @brief Sends data over the MCTP socket.
 *
 * This function sends the provided buffer over the MCTP socket. It attempts to
 * send the entire buffer in a loop, handling partial sends by continuing until
 * all data is sent. If an error occurs during sending, it logs the error and
 * returns an error status.
 *
 * @param buf The buffer containing the data to be sent.
 * @param timeout The timeout value for the operation (not used in this
 * implementation).
 * @return RetStat::OK if the data is sent successfully, RetStat::ERROR_UNKNOWN
 * otherwise.
 */
inline RetStat MctpIoClass::write(const std::vector<uint8_t>& buf,
                                  [[maybe_unused]] timeout_us_t /*timeout*/)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    ssize_t sent = 0;
    ssize_t toSend = static_cast<ssize_t>(buf.size());

    while (sent < toSend)
    {
        ssize_t ret = send(Socket, (void*)&buf[static_cast<size_t>(sent)],
                           static_cast<size_t>(toSend - sent), 0);
        if (ret <= 0)
        {
            if (Log.logLevel >= LogClass::Level::Critical)
            {
                Log.iprint("Send error:");
                Log.println(errno);
            }
            return RetStat::ERROR_UNKNOWN;
        }
        sent += ret;
    }
    return RetStat::OK;
}

/**
 * @brief Reads data from the MCTP socket.
 *
 * This function reads data from the MCTP socket into the provided buffer. It
 * resizes the buffer to the maximum message size and attempts to read data from
 * the socket. If an error occurs or no data is received, it logs the error and
 * clears the buffer. The buffer is then resized to the actual amount of data
 * received.
 *
 * @param buf The buffer to store the received data.
 * @param timeout The timeout value for the operation (not used in this
 * implementation).
 * @return RetStat::OK if the data is read successfully, RetStat::ERROR_UNKNOWN
 * otherwise.
 */
inline RetStat MctpIoClass::read(std::vector<uint8_t>& buf,
                                 [[maybe_unused]] timeout_us_t /*timeout*/)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    buf.resize(mctpMaxMessageSize);
    ssize_t result = recv(Socket, (void*)buf.data(), buf.size(), 0);
    if (result == -1 || result == 0)
    {
        buf.clear();
        if (Log.logLevel >= LogClass::Level::Critical)
        {
            Log.iprint("Receive error: ");
            Log.println(errno);
        }
        return RetStat::ERROR_UNKNOWN;
    }
    buf.resize(result);
    return RetStat::OK;
}
#endif

} // namespace spdmcpp
