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

struct PacketCertificateResponseMin
{
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_CERTIFICATE;
    static constexpr bool sizeIsConstant = true;

    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);
    uint16_t PortionLength = 0;
    uint16_t RemainderLength = 0;

    void printMl(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational) {
            SPDMCPP_LOG_INDENT(log);
            SPDMCPP_LOG_printMl(log, Header);
            SPDMCPP_LOG_iexprln(log, PortionLength);
            SPDMCPP_LOG_iexprln(log, RemainderLength);
        }
    }

    bool operator==(const PacketCertificateResponseMin& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endianHostSpdmCopy(const PacketCertificateResponseMin& src,
                               PacketCertificateResponseMin& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
    endianHostSpdmCopy(src.PortionLength, dst.PortionLength);
    endianHostSpdmCopy(src.RemainderLength, dst.RemainderLength);
}

struct PacketCertificateResponseVar
{
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_CERTIFICATE;
    static constexpr bool sizeIsConstant = false;

    PacketCertificateResponseMin Min;
    std::vector<uint8_t> CertificateVector;

    bool operator==(const PacketCertificateResponseVar& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        if (CertificateVector != other.CertificateVector)
        {
            return false;
        }
        return true;
    }

    RetStat finalize()
    {
        Min.PortionLength = CertificateVector.size();
        return RetStat::OK;
    }

    void printMl(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational) {
            SPDMCPP_LOG_INDENT(log);
            SPDMCPP_LOG_printMl(log, Min);
            SPDMCPP_LOG_iexprln(log, CertificateVector.size());
            if (!CertificateVector.empty())
            {
                {
                    SPDMCPP_LOG_iexprln(log, CertificateVector);
                }
            }
        }
    }
};

[[nodiscard]] inline RetStat
    packetEncodeInternal(const PacketCertificateResponseVar& p,
                         std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetEncodeInternal(p.Min, buf, off);

    packetEncodeBasic(p.CertificateVector, buf, off);
    return rs;
}

[[nodiscard]] inline RetStat
    packetDecodeInternal(spdmcpp::LogClass& logg,PacketCertificateResponseVar& p,
                         const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetDecodeInternal(logg, p.Min, buf, off);
    if (isError(rs))
    {
        {
            return rs;
        }
    }

    p.CertificateVector.resize(p.Min.PortionLength);
    memcpy(p.CertificateVector.data(), &buf[off], p.CertificateVector.size());
    off += p.CertificateVector.size();

    return RetStat::OK;
}

#endif
