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




#include "../../packet.hpp"

#pragma once



#ifdef SPDMCPP_PACKET_HPP

struct PacketAlgorithmsResponseMin
{
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_ALGORITHMS;
    static constexpr bool sizeIsConstant = true;

    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);
    uint16_t Length = 0;
    uint8_t MeasurementSpecification = 0;
    uint8_t Reserved0 = 0;
    MeasurementHashAlgoFlags MeasurementHashAlgo =
        MeasurementHashAlgoFlags::NIL;
    BaseAsymAlgoFlags BaseAsymAlgo = BaseAsymAlgoFlags::NIL;
    BaseHashAlgoFlags BaseHashAlgo = BaseHashAlgoFlags::NIL;
    uint32_t Reserved1 = 0;
    uint32_t Reserved2 = 0;
    uint32_t Reserved3 = 0;
    uint8_t ExtAsymCount = 0;
    uint8_t ExtHashCount = 0;
    uint16_t Reserved4 = 0;

    void printMl(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational) {
            SPDMCPP_LOG_INDENT(log);
            SPDMCPP_LOG_printMl(log, Header);
            SPDMCPP_LOG_iexprln(log, Length);
            SPDMCPP_LOG_iexprln(log, MeasurementSpecification);
            SPDMCPP_LOG_iexprln(log, Reserved0);
            SPDMCPP_LOG_iflagsln(log, MeasurementHashAlgo);
            SPDMCPP_LOG_iflagsln(log, BaseAsymAlgo);
            SPDMCPP_LOG_iflagsln(log, BaseHashAlgo);
            SPDMCPP_LOG_iexprln(log, Reserved1);
            SPDMCPP_LOG_iexprln(log, Reserved2);
            SPDMCPP_LOG_iexprln(log, Reserved3);
            SPDMCPP_LOG_iexprln(log, ExtAsymCount);
            SPDMCPP_LOG_iexprln(log, ExtHashCount);
            SPDMCPP_LOG_iexprln(log, Reserved4);
        }
    }

    bool operator==(const PacketAlgorithmsResponseMin& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endianHostSpdmCopy(const PacketAlgorithmsResponseMin& src,
                               PacketAlgorithmsResponseMin& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
    endianHostSpdmCopy(src.Length, dst.Length);
    endianHostSpdmCopy(src.MeasurementSpecification,
                       dst.MeasurementSpecification);
    endianHostSpdmCopy(src.Reserved0, dst.Reserved0);
    endianHostSpdmCopy(src.MeasurementHashAlgo, dst.MeasurementHashAlgo);
    endianHostSpdmCopy(src.BaseAsymAlgo, dst.BaseAsymAlgo);
    endianHostSpdmCopy(src.BaseHashAlgo, dst.BaseHashAlgo);
    endianHostSpdmCopy(src.Reserved1, dst.Reserved1);
    endianHostSpdmCopy(src.Reserved2, dst.Reserved2);
    endianHostSpdmCopy(src.Reserved3, dst.Reserved3);
    endianHostSpdmCopy(src.ExtAsymCount, dst.ExtAsymCount);
    endianHostSpdmCopy(src.ExtHashCount, dst.ExtHashCount);
    endianHostSpdmCopy(src.Reserved4, dst.Reserved4);
}

struct PacketAlgorithmsResponseVar
{
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_ALGORITHMS;
    static constexpr bool sizeIsConstant = false;

    PacketAlgorithmsResponseMin Min;
    std::vector<PacketReqAlgStruct> PacketReqAlgVector;

    uint16_t getSize() const
    {
        size_t size = 0;
        size += sizeof(Min);
        size += std::accumulate(
            PacketReqAlgVector.begin(), PacketReqAlgVector.end(), 0,
            [](size_t a, const auto& iter) { return a + iter.getSize(); });
        SPDMCPP_ASSERT(size <= std::numeric_limits<uint16_t>::max());
        return static_cast<uint16_t>(size);
    }
    RetStat finalize()
    {
        if (PacketReqAlgVector.size() >= 256)
        {
            return RetStat::ERROR_UNKNOWN;
        }
        Min.Header.Param1 = static_cast<uint8_t>(PacketReqAlgVector.size());
        Min.Length = getSize();
        return RetStat::OK;
    }

    bool operator==(const PacketAlgorithmsResponseVar& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        if (PacketReqAlgVector != other.PacketReqAlgVector)
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
            SPDMCPP_LOG_iexprln(log, PacketReqAlgVector.size());
            for (size_t i = 0; i < PacketReqAlgVector.size(); ++i)
            {
                log.iprint("PacketReqAlgVector[" + std::to_string(i) +
                           "]: "); // TODO something more optimal
                PacketReqAlgVector[i].print(log);
                log.endl();
            }
        }
    }
};

[[nodiscard]] inline RetStat
    packetEncodeInternal(const PacketAlgorithmsResponseVar& p,
                         std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetEncodeInternal(p.Min, buf, off);
    if (isError(rs))
    {
        return rs;
    }

    for (const auto& iter : p.PacketReqAlgVector)
    {
        rs = packetEncodeInternal(iter, buf, off);
        if (isError(rs))
        {
            return rs;
        }
    }
    return rs;
}

[[nodiscard]] inline RetStat
    packetDecodeInternal(spdmcpp::LogClass& logg,PacketAlgorithmsResponseVar& p,
                         const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetDecodeInternal(logg, p.Min, buf, off);
    if (isError(rs))
    {
        {
            return rs;
        }
    }

    p.PacketReqAlgVector.resize(p.Min.Header.Param1);
    for (auto& iter : p.PacketReqAlgVector)
    {
        rs = packetDecodeInternal(logg,iter, buf, off);
        if (isError(rs))
        {
            return rs;
        }
    }
    return rs;
}

#endif
