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

#pragma once

#include "../../packet.hpp"

#ifdef SPDMCPP_PACKET_HPP

struct PacketGetMeasurementsRequestMin
{
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::REQUEST_GET_MEASUREMENTS;
    static constexpr bool sizeIsConstant = true;

    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);

    bool hasNonce() const
    {
        return Header.Param1 & 0x01;
    }
    void setNonce()
    {
        Header.Param1 |= 0x01;
    }

    void printMl(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational) {
            SPDMCPP_LOG_INDENT(log);
            SPDMCPP_LOG_printMl(log, Header);
        }
    }

    bool operator==(const PacketGetMeasurementsRequestMin& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endianHostSpdmCopy(const PacketGetMeasurementsRequestMin& src,
                               PacketGetMeasurementsRequestMin& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
}

struct PacketGetMeasurementsRequestVar
{
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::REQUEST_GET_MEASUREMENTS;
    static constexpr bool sizeIsConstant = false;

    PacketGetMeasurementsRequestMin Min;
    nonce_array_32 Nonce = {0};
    uint8_t SlotIDParam = 0;

    bool hasNonce() const
    {
        return Min.hasNonce();
    }
    void setNonce()
    {
        Min.setNonce();
    }

    uint16_t getSize() const
    {
        uint16_t size = 0;
        size += sizeof(Min);
        if (Min.hasNonce())
        {
            size += sizeof(Nonce);
            if (Min.Header.MessageVersion != MessageVersionEnum::SPDM_1_0)
            {
                size += sizeof(SlotIDParam);
            }
        }
        return size;
    }

    bool operator==(const PacketGetMeasurementsRequestVar& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }

        if (!isEqual(Nonce, other.Nonce))
        {
            return false;
        }
        if (SlotIDParam != other.SlotIDParam)
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
            SPDMCPP_LOG_iexprln(log, Nonce);
            SPDMCPP_LOG_iexprln(log, SlotIDParam);
        }
    }
};

[[nodiscard]] inline RetStat
    packetEncodeInternal(const PacketGetMeasurementsRequestVar& p,
                         std::vector<uint8_t>& buf, size_t& off)
{
    size_t size = p.getSize();
    buf.resize(off + size);

    auto rs = packetEncodeInternal(p.Min, buf, off);
    if (isError(rs))
    {
        {
            return rs;
        }
    }

    if (p.hasNonce())
    {
        packetEncodeBasic(p.Nonce, buf, off);
        if (p.Min.Header.MessageVersion != MessageVersionEnum::SPDM_1_0)
        {
            packetEncodeBasic(p.SlotIDParam, buf, off);
        }
    }
    return rs;
}

[[nodiscard]] inline RetStat
    packetDecodeInternal(spdmcpp::LogClass& logg,PacketGetMeasurementsRequestVar& p,
                         const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetDecodeInternal(logg, p.Min, buf, off);
    if (isError(rs))
    {
        {
            return rs;
        }
    }

    if (p.hasNonce())
    {
        rs = packetDecodeBasic(logg, p.Nonce, buf, off);
        if (isError(rs))
        {
            {
                return rs;
            }
        }

        if (p.Min.Header.MessageVersion != MessageVersionEnum::SPDM_1_0)
        {
            rs = packetDecodeBasic(logg, p.SlotIDParam, buf, off);
            if (isError(rs))
            {
                {
                    return rs;
                }
            }
        }
    }

    return rs;
}

#endif
