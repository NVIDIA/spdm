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

#include "../../packet.hpp"

#ifdef SPDMCPP_PACKET_HPP

struct PacketErrorResponseMin
{
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_ERROR;
    static constexpr bool sizeIsConstant = true;

    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);

    void print(LogClass& log) const
    {
        Header.print(log);
        // TODO handle custom data
    }

    void printMl(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational)
        {
            SPDMCPP_LOG_INDENT(log);
            SPDMCPP_LOG_printMl(log, Header);
        }
    }

    bool operator==(const PacketErrorResponseMin& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endianHostSpdmCopy(const PacketErrorResponseMin& src,
                               PacketErrorResponseMin& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
}

struct PacketErrorResponseVar
{
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_ERROR;
    static constexpr bool sizeIsConstant = false;

    PacketErrorResponseMin Min;
    std::vector<uint8_t> ExtendedErrorData;
    // TODO handle custom data

    bool operator==(const PacketErrorResponseVar& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        if (ExtendedErrorData != other.ExtendedErrorData)
        {
            return false;
        }
        return true;
    }

    void printMl(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational)
        {
            SPDMCPP_LOG_INDENT(log);
            SPDMCPP_LOG_printMl(log, Min);
            SPDMCPP_LOG_iexprln(log, ExtendedErrorData);
        }
    }
    enum ExtendedErrorNotReadyOffs : size_t
    {
        ExtErrOffsNotReadyRTDExponent = 0,
        ExtErrOffsReadyRequestCode = 1,
        ExtErrOffsNotReadyToken = 2,
        ExtErrOffsNotReadyRTDM = 3,
        ExtErrOffsEOE
    };
    enum ErrorCodes : uint8_t
    {
        ErrorCodeInvalidRequest = 0x01,
        ErrorCodeBusy = 0x03,
        ErrorCodeResponseNotReady = 0x42,
    };
};

[[nodiscard]] inline RetStat
    packetDecodeInternal(spdmcpp::LogClass& logg, PacketErrorResponseVar& p,
                         const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetDecodeInternal(logg, p.Min, buf, off);
    if (isError(rs))
    {
        return rs;
    }
    const auto extErrDataSize = buf.size() - off;
    if (extErrDataSize > 0)
    {
        p.ExtendedErrorData.resize(extErrDataSize);
        rs = packetDecodeBasic(logg, p.ExtendedErrorData, buf, off);
    }
    return rs;
}

[[nodiscard]] inline RetStat
    packetEncodeInternal(const PacketErrorResponseVar& p,
                         std::vector<uint8_t>& buf, size_t& off)
{
    // TODO handle custom data
    auto rs = packetEncodeInternal(p.Min, buf, off);
    if (isError(rs))
    {
        return rs;
    }
    if (!p.ExtendedErrorData.empty())
    {
        packetEncodeBasic(p.ExtendedErrorData, buf, off);
    }
    return rs;
}

#endif
