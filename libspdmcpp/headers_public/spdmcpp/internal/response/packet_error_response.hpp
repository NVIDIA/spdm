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
        if (log.logLevel >= LogClass::Level::Informational) {
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
    // TODO handle custom data

    bool operator==(const PacketErrorResponseVar& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        return true;
    }

    void printMl(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational) {
            SPDMCPP_LOG_INDENT(log);
            SPDMCPP_LOG_printMl(log, Min);
        }
    }
};

[[nodiscard]] inline RetStat
    packetDecodeInternal(spdmcpp::LogClass& logg,PacketErrorResponseVar& p,
                         const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetDecodeInternal(logg,p.Min, buf, off);
    // TODO handle custom data
    return rs;
}
[[nodiscard]] inline RetStat
    packetEncodeInternal(const PacketErrorResponseVar& p,
                         std::vector<uint8_t>& buf, size_t& off)
{
    // TODO handle custom data
    auto rs = packetEncodeInternal(p.Min, buf, off);
    return rs;
}

#endif
