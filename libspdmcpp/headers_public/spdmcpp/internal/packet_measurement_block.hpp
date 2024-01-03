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

#include "../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct PacketMeasurementBlockMin
{
    uint8_t Index = 0;
    uint8_t MeasurementSpecification = 0; // TODO enum?
    uint16_t MeasurementSize = 0;

    static constexpr bool sizeIsConstant = true;

    void printMl(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational) {
            SPDMCPP_LOG_INDENT(log);
            SPDMCPP_LOG_iexprln(log, Index);
            log.print("   ");
            SPDMCPP_LOG_iexprln(log, MeasurementSpecification);
            log.print("   ");
            SPDMCPP_LOG_iexprln(log, MeasurementSize);
            log.print("   ");
        }
    }

    bool operator==(const PacketMeasurementBlockMin& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endianHostSpdmCopy(const PacketMeasurementBlockMin& src,
                               PacketMeasurementBlockMin& dst)
{
    endianHostSpdmCopy(src.Index, dst.Index);
    endianHostSpdmCopy(src.MeasurementSpecification,
                       dst.MeasurementSpecification);
    endianHostSpdmCopy(src.MeasurementSize, dst.MeasurementSize);
}

struct PacketMeasurementBlockVar
{
    PacketMeasurementBlockMin Min;
    std::vector<uint8_t> MeasurementVector;

    static constexpr bool sizeIsConstant = false;

    uint32_t getSize() const
    {
        size_t size = 0;
        size += sizeof(Min);
        SPDMCPP_ASSERT(MeasurementVector.size() <=
                       std::numeric_limits<uint16_t>::max());
        size += MeasurementVector.size();
        SPDMCPP_ASSERT(size <= std::numeric_limits<uint32_t>::max());
        return static_cast<uint32_t>(size);
    }
    RetStat finalize()
    {
        if (MeasurementVector.size() >= std::numeric_limits<uint16_t>::max())
        {
            return RetStat::ERROR_UNKNOWN;
        }
        Min.MeasurementSize = static_cast<uint16_t>(MeasurementVector.size());
        return RetStat::OK;
    }

    bool operator==(const PacketMeasurementBlockVar& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        if (MeasurementVector != other.MeasurementVector)
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
            SPDMCPP_LOG_iexprln(log, MeasurementVector);
        }
    }
};

[[nodiscard]] inline RetStat
    packetEncodeInternal(const PacketMeasurementBlockVar& p,
                         std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetEncodeInternal(p.Min, buf, off);
    if (isError(rs))
    {
        return rs;
    }
    packetEncodeBasic(p.MeasurementVector, buf, off);
    return rs;
}

[[nodiscard]] inline RetStat
    packetDecodeInternal(spdmcpp::LogClass& logg,PacketMeasurementBlockVar& p,
                         const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetDecodeBasic(logg, p.Min, buf, off);
    if (isError(rs))
    {
        {
            return rs;
        }
    }
    p.MeasurementVector.resize(p.Min.MeasurementSize);
    rs = packetDecodeBasic(logg, p.MeasurementVector, buf, off);
    return rs;
}

#endif
