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

struct PacketGetCapabilitiesRequest
{
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::REQUEST_GET_CAPABILITIES;
    static constexpr bool sizeIsConstant = false;

    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);
    uint8_t Reserved0 = 0;
    uint8_t CTExponent = 0;
    uint16_t Reserved1 = 0;
    RequesterCapabilitiesFlags Flags = RequesterCapabilitiesFlags::NIL;
    // SPDM 1.2 fields (only present in SPDM 1.2+)
    uint32_t DataTransferSize = 0;
    uint32_t MaxSPDMmsgSize = 0;

    uint16_t getSize() const
    {
        uint16_t size = sizeof(Header) + sizeof(Reserved0) +
                        sizeof(CTExponent) + sizeof(Reserved1) + sizeof(Flags);
        // Add SPDM 1.2 fields if version is 1.2 or higher
        if (Header.MessageVersion >= MessageVersionEnum::SPDM_1_2)
        {
            size += sizeof(DataTransferSize) + sizeof(MaxSPDMmsgSize);
        }
        return size;
    }

    PacketGetCapabilitiesRequest() = default;
    PacketGetCapabilitiesRequest(uint8_t ctExponent,
                                 RequesterCapabilitiesFlags flags) :
        CTExponent(ctExponent), Flags(flags)
    {}
    PacketGetCapabilitiesRequest(uint8_t ctExponent,
                                 RequesterCapabilitiesFlags flags,
                                 uint32_t dataTransferSize,
                                 uint32_t maxSPDMmsgSize) :
        CTExponent(ctExponent), Flags(flags),
        DataTransferSize(dataTransferSize), MaxSPDMmsgSize(maxSPDMmsgSize)
    {}

    void printMl(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational)
        {
            SPDMCPP_LOG_INDENT(log);
            SPDMCPP_LOG_printMl(log, Header);
            SPDMCPP_LOG_iexprln(log, Reserved0);
            SPDMCPP_LOG_iexprln(log, CTExponent);
            SPDMCPP_LOG_iexprln(log, Reserved1);
            SPDMCPP_LOG_iflagsln(log, Flags);
            SPDMCPP_LOG_iexprln(log, DataTransferSize);
            SPDMCPP_LOG_iexprln(log, MaxSPDMmsgSize);
        }
    }
};

inline void endianHostSpdmCopy(const PacketGetCapabilitiesRequest& src,
                               PacketGetCapabilitiesRequest& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
    endianHostSpdmCopy(src.Reserved0, dst.Reserved0);
    endianHostSpdmCopy(src.CTExponent, dst.CTExponent);
    endianHostSpdmCopy(src.Reserved1, dst.Reserved1);
    endianHostSpdmCopy(src.Flags, dst.Flags);
    endianHostSpdmCopy(src.DataTransferSize, dst.DataTransferSize);
    endianHostSpdmCopy(src.MaxSPDMmsgSize, dst.MaxSPDMmsgSize);
}

/** @brief Encode a PacketGetCapabilitiesRequest
 *  @param p The packet to encode
 *  @param buf The buffer to encode to
 *  @param off The offset to encode at
 *  @return RetStat::OK if the encoding is successful, otherwise an error code
 */
[[nodiscard]] inline RetStat
    packetEncodeInternal(const PacketGetCapabilitiesRequest& p,
                         std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetEncodeInternal(p.Header, buf, off);
    if (isError(rs))
        return rs;

    packetEncodeBasic(p.Reserved0, buf, off);
    packetEncodeBasic(p.CTExponent, buf, off);
    packetEncodeBasic(p.Reserved1, buf, off);
    packetEncodeBasic(p.Flags, buf, off);

    // Only encode SPDM 1.2 fields if version is 1.2 or higher
    if (p.Header.MessageVersion >= MessageVersionEnum::SPDM_1_2)
    {
        packetEncodeBasic(p.DataTransferSize, buf, off);
        packetEncodeBasic(p.MaxSPDMmsgSize, buf, off);
    }

    return RetStat::OK;
}

/** @brief Decode a PacketGetCapabilitiesRequest
 *  @param logg The log class to use
 *  @param p The packet to decode to
 *  @param buf The buffer to decode from
 *  @param off The offset to decode at
 *  @return RetStat::OK if the decoding is successful, otherwise an error
 */
[[nodiscard]] inline RetStat
    packetDecodeInternal(spdmcpp::LogClass& logg,
                         PacketGetCapabilitiesRequest& p,
                         const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetDecodeInternal(logg, p.Header, buf, off);
    if (isError(rs))
        return rs;

    rs = packetDecodeBasic(logg, p.Reserved0, buf, off);
    if (isError(rs))
        return rs;

    rs = packetDecodeBasic(logg, p.CTExponent, buf, off);
    if (isError(rs))
        return rs;

    rs = packetDecodeBasic(logg, p.Reserved1, buf, off);
    if (isError(rs))
        return rs;

    rs = packetDecodeBasic(logg, p.Flags, buf, off);
    if (isError(rs))
        return rs;

    // Only decode SPDM 1.2 fields if version is 1.2 or higher
    if (p.Header.MessageVersion >= MessageVersionEnum::SPDM_1_2)
    {
        rs = packetDecodeBasic(logg, p.DataTransferSize, buf, off);
        if (isError(rs))
            return rs;

        rs = packetDecodeBasic(logg, p.MaxSPDMmsgSize, buf, off);
        if (isError(rs))
            return rs;
    }
    else
    {
        // Set to 0 for SPDM 1.1
        p.DataTransferSize = 0;
        p.MaxSPDMmsgSize = 0;
    }

    return RetStat::OK;
}

#endif
