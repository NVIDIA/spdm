/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
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

struct PacketDigestsResponseMin
{
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_DIGESTS;
    static constexpr bool sizeIsConstant = true;

    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);

    void printMl(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational) {
            SPDMCPP_LOG_INDENT(log);
            SPDMCPP_LOG_printMl(log, Header);
        }
    }

    bool operator==(const PacketDigestsResponseMin& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endianHostSpdmCopy(const PacketDigestsResponseMin& src,
                               PacketDigestsResponseMin& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
}

struct PacketDigestsResponseVar
{
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_DIGESTS;
    static constexpr bool sizeIsConstant = false;

    PacketDigestsResponseMin Min;

    static constexpr uint8_t digestsNum = 8;
    std::array<std::vector<uint8_t>, digestsNum> Digests;

    RetStat finalize()
    {
        Min.Header.Param2 = 0;
        for (uint8_t i = 0; i < digestsNum; ++i)
        {
            if (!Digests[i].empty())
            {
                Min.Header.Param2 |= 1 << i;
            }
        }
        return RetStat::OK;
    }

    bool operator==(const PacketDigestsResponseVar& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        for (uint8_t i = 0; i < digestsNum; ++i)
        {
            if (Digests[i] != other.Digests[i])
            {
                return false;
            }
        }
        return true;
    }

    void printMl(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational) {
            SPDMCPP_LOG_INDENT(log);
            SPDMCPP_LOG_printMl(log, Min);
            for (uint8_t i = 0; i < digestsNum; ++i)
            {
                log.iprint("Digests[" + std::to_string(i) +
                           "]: "); // TODO something more optimal
                log.print(Digests[i]);
                log.endl();
            }
        }
    }
};

[[nodiscard]] inline RetStat
    packetEncodeInternal(const PacketDigestsResponseVar& p,
                         std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetEncodeInternal(p.Min, buf, off);

    for (uint8_t i = 0; i < PacketDigestsResponseVar::digestsNum; ++i)
    {
        if ((1 << i) & p.Min.Header.Param2)
        {
            packetEncodeBasic(p.Digests[i], buf, off);
        }
    }
    return rs;
}

[[nodiscard]] inline RetStat
    packetDecodeInternal(spdmcpp::LogClass& logg,PacketDigestsResponseVar& p,
                         const std::vector<uint8_t>& buf, size_t& off,
                         const PacketDecodeInfo& info)
{
    auto rs = packetDecodeInternal(logg, p.Min, buf, off);
    if (isError(rs))
    {
            return rs;
    }

    //     p.Digests.resize(countBits(
    //         p.Min.Header.Param2)); // TODO check size for reasonable limit!!
    for (uint8_t i = 0; i < PacketDigestsResponseVar::digestsNum; ++i)
    {
        if ((1 << i) & p.Min.Header.Param2)
        {
            p.Digests[i].resize(info.BaseHashSize);
            rs = packetDecodeBasic(logg, p.Digests[i], buf, off);
            if (isError(rs))
            {
                return rs;
            }
        }
    }
    return RetStat::OK;
}

#endif
