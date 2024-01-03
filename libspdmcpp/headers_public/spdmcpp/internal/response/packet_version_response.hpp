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

struct PacketVersionResponseMin
{
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_VERSION;
    static constexpr bool sizeIsConstant =
        true; // TODO decide how we need/want to handle such packets

    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);
    uint8_t Reserved = 0;
    //    uint8_t VersionNumberEntryCount = 0;

    void printMl(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational) {
            SPDMCPP_LOG_INDENT(log);
            SPDMCPP_LOG_printMl(log, Header);
            SPDMCPP_LOG_iexprln(log, Reserved);
            // SPDMCPP_LOG_iexprln(log, VersionNumberEntryCount);
        }
    }

    bool operator==(const PacketVersionResponseMin& other) const
    {
        // TODO should only compare the valid portion of AlgSupported,
        // AlgExternal?
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endianHostSpdmCopy(const PacketVersionResponseMin& src,
                               PacketVersionResponseMin& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
    endianHostSpdmCopy(src.Reserved, dst.Reserved);
    // endianHostSpdmCopy(src.VersionNumberEntryCount,
    //   dst.VersionNumberEntryCount);
}

struct PacketVersionResponseVar
{
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_VERSION;
    static constexpr bool sizeIsConstant = false;

    PacketVersionResponseMin Min;
    std::vector<PacketVersionNumber> VersionNumberEntries;

    void printMl(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational) {
            SPDMCPP_LOG_INDENT(log);
            SPDMCPP_LOG_printMl(log, Min);

            for (size_t i = 0; i < VersionNumberEntries.size(); ++i)
            {
                log.iprint("VersionNumberEntries[" + std::to_string(i) +
                           "]: "); // TODO something more optimal
                VersionNumberEntries[i].print(log);
                log.endl();
            }
        }
    }

    bool operator==(const PacketVersionResponseVar& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        if (VersionNumberEntries != other.VersionNumberEntries)
        {
            return false;
        }
        return true;
    }
};

[[nodiscard]] inline RetStat
    packetDecodeInternal(spdmcpp::LogClass& logg,PacketVersionResponseVar& p,
                         const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetDecodeInternal(logg,p.Min, buf, off);
    if (rs != RetStat::OK)
    {
        return rs;
    }
    {
        uint8_t size = 0;
        rs = packetDecodeBasic(logg,size, buf, off);
        if (rs != RetStat::OK)
        {
            return rs;
        }
        p.VersionNumberEntries.resize(size);
    }
    for (auto& iter : p.VersionNumberEntries)
    {
        rs = packetDecodeInternal(logg, iter, buf, off);
        if (rs != RetStat::OK)
        {
            return rs;
        }
    }
    return RetStat::OK;
}

[[nodiscard]] inline RetStat
    packetEncodeInternal(const PacketVersionResponseVar& p,
                         std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetEncodeInternal(p.Min, buf, off);
    if (rs != RetStat::OK)
    {
        return rs;
    }

    {
        uint8_t size = p.VersionNumberEntries.size();
        packetEncodeBasic(size, buf, off);
    }
    for (const auto& iter : p.VersionNumberEntries)
    {
        rs = packetEncodeInternal(iter, buf, off);
        if (rs != RetStat::OK)
        {
            return rs;
        }
    }
    return RetStat::OK;
}

#endif
