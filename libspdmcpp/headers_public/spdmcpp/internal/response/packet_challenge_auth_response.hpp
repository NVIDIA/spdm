
#pragma once

#include "../../packet.hpp"

#ifdef SPDMCPP_PACKET_HPP

struct PacketChallengeAuthResponseMin
{
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_CHALLENGE_AUTH;
    static constexpr bool sizeIsConstant = true;

    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);

    void printMl(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational) {
            SPDMCPP_LOG_INDENT(log);
            SPDMCPP_LOG_printMl(log, Header);
        }
    }

    bool operator==(const PacketChallengeAuthResponseMin& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endianHostSpdmCopy(const PacketChallengeAuthResponseMin& src,
                               PacketChallengeAuthResponseMin& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
}

struct PacketChallengeAuthResponseVar
{
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_CHALLENGE_AUTH;
    static constexpr bool sizeIsConstant = false;

    PacketChallengeAuthResponseMin Min;
    nonce_array_32 Nonce = {0};
    std::vector<uint8_t> CertChainHashVector;
    std::vector<uint8_t> MeasurementSummaryHashVector;
    std::vector<uint8_t> OpaqueDataVector;
    std::vector<uint8_t> SignatureVector;

    RetStat finalize()
    {
        return RetStat::OK;
    }

    bool operator==(const PacketChallengeAuthResponseVar& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        if (!isEqual(Nonce, other.Nonce))
        {
            return false;
        }
        if (CertChainHashVector != other.CertChainHashVector)
        {
            return false;
        }
        if (MeasurementSummaryHashVector != other.MeasurementSummaryHashVector)
        {
            return false;
        }
        if (OpaqueDataVector != other.OpaqueDataVector)
        {
            return false;
        }
        if (SignatureVector != other.SignatureVector)
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
            SPDMCPP_LOG_iexprln(log, CertChainHashVector);
            SPDMCPP_LOG_iexprln(log, MeasurementSummaryHashVector);
            SPDMCPP_LOG_iexprln(log, OpaqueDataVector);
            SPDMCPP_LOG_iexprln(log, SignatureVector);
        }
    }
};

[[nodiscard]] inline RetStat
    packetEncodeInternal(const PacketChallengeAuthResponseVar& p,
                         std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetEncodeInternal(p.Min, buf, off);
    if (isError(rs))
    {
        {
            return rs;
        }
    }

    packetEncodeBasic(p.CertChainHashVector, buf, off);

    packetEncodeBasic(p.Nonce, buf, off);

    if (!p.MeasurementSummaryHashVector.empty())
    {
        packetEncodeBasic(p.MeasurementSummaryHashVector, buf, off);
    }

    // TODO verify no greater than 1024
    packetEncodeBasic(static_cast<uint16_t>(p.OpaqueDataVector.size()), buf,
                      off);
    packetEncodeBasic(p.OpaqueDataVector, buf, off);

    packetEncodeBasic(p.SignatureVector, buf, off);

    return rs;
}

[[nodiscard]] inline RetStat
    packetDecodeInternal(PacketChallengeAuthResponseVar& p,
                         const std::vector<uint8_t>& buf, size_t& off,
                         const PacketDecodeInfo& info)
{
    auto rs = packetDecodeInternal(p.Min, buf, off);
    if (isError(rs))
    {
        {
            return rs;
        }
    }

    p.CertChainHashVector.resize(info.BaseHashSize);
    rs = packetDecodeBasic(p.CertChainHashVector, buf, off);
    if (isError(rs))
    {
        {
            return rs;
        }
    }

    rs = packetDecodeBasic(p.Nonce, buf, off);
    if (isError(rs))
    {
        {
            return rs;
        }
    }

    if (info.ChallengeParam2)
    {
        p.MeasurementSummaryHashVector.resize(info.BaseHashSize);
        rs = packetDecodeBasic(p.MeasurementSummaryHashVector, buf, off);
        if (isError(rs))
        {
            {
                return rs;
            }
        }
    }
    {
        uint16_t length = 0;
        rs = packetDecodeBasic(length, buf,
                               off); // TODO verify no greater than 1024
        if (isError(rs))
        {
            {
                return rs;
            }
        }
        p.OpaqueDataVector.resize(length);
        rs = packetDecodeBasic(p.OpaqueDataVector, buf, off);
        if (isError(rs))
        {
            {
                return rs;
            }
        }
    }
    p.SignatureVector.resize(info.SignatureSize);
    rs = packetDecodeBasic(p.SignatureVector, buf, off);
    return rs;
}

#endif
