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

struct PacketMeasurementFieldMin
{
    uint8_t Type = 0;
    uint16_t Size = 0;

    static constexpr bool sizeIsConstant = true;

    void printMl(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational) {
            SPDMCPP_LOG_INDENT(log);
            SPDMCPP_LOG_iexprln(log, Type);
            log.print("   ");
        }
    }

    bool operator==(const PacketMeasurementFieldMin& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endianHostSpdmCopy(const PacketMeasurementFieldMin& src,
                               PacketMeasurementFieldMin& dst)
{
    endianHostSpdmCopy(src.Type, dst.Type);
    endianHostSpdmCopy(src.Size, dst.Size);
}

struct PacketMeasurementFieldVar
{
    PacketMeasurementFieldMin Min;
    std::vector<uint8_t> ValueVector;

    static constexpr bool sizeIsConstant = false;

    RetStat finalize()
    {
        if (ValueVector.size() >= std::numeric_limits<uint16_t>::max())
        {
            return RetStat::ERROR_UNKNOWN;
        }
        Min.Size = static_cast<uint16_t>(ValueVector.size());
        return RetStat::OK;
    }

    bool operator==(const PacketMeasurementFieldVar& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        if (ValueVector != other.ValueVector)
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
            SPDMCPP_LOG_iexprln(log, ValueVector);
        }
    }
};

[[nodiscard]] inline RetStat
    packetEncodeInternal(const PacketMeasurementFieldVar& p,
                         std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetEncodeInternal(p.Min, buf, off);
    if (isError(rs))
    {
        return rs;
    }
    packetEncodeBasic(p.ValueVector, buf, off);
    return rs;
}

[[nodiscard]] inline RetStat
    packetDecodeInternal(spdmcpp::LogClass& logg,PacketMeasurementFieldVar& p,
                         const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetDecodeBasic(logg, p.Min, buf, off);
    if (isError(rs))
    {
        {
            return rs;
        }
    }

    p.ValueVector.resize(p.Min.Size);
    rs = packetDecodeBasic(logg, p.ValueVector, buf, off);
    return rs;
}

#endif
