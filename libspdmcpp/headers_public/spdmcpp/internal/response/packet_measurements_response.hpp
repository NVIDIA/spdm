
#include "../../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct PacketMeasurementsResponseMin
{
    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);
    uint8_t NumberOfBlocks = 0;
    std::array<uint8_t, 3> MeasurementRecordLength = {0, 0, 0}; // wtf dmtf...

    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_MEASUREMENTS;
    static constexpr bool sizeIsConstant = true;

    uint32_t getMeasurementRecordLength() const
    {
        return MeasurementRecordLength[0] | MeasurementRecordLength[1] << 8 |
               MeasurementRecordLength[2] << 16;
    }
    bool setMeasurementRecordLength(uint32_t len)
    {
        if (len >= 1 << 24)
        {
            return false;
        }
        MeasurementRecordLength[0] = len & 0xFF;
        MeasurementRecordLength[1] = (len >> 8) & 0xFF;
        MeasurementRecordLength[2] = (len >> 16) & 0xFF;
        return true;
    }

    void printMl(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_printMl(log, Header);
        SPDMCPP_LOG_iexprln(log, NumberOfBlocks);
        SPDMCPP_LOG_iexprln(log, MeasurementRecordLength);
    }

    bool operator==(const PacketMeasurementsResponseMin& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endianHostSpdmCopy(const PacketMeasurementsResponseMin& src,
                               PacketMeasurementsResponseMin& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
    endianHostSpdmCopy(src.NumberOfBlocks, dst.NumberOfBlocks);
#if SPDMCPP_ENDIAN_SWAP
    dst.MeasurementRecordLength[0] = src.MeasurementRecordLength[2];
    dst.MeasurementRecordLength[1] = src.MeasurementRecordLength[1];
    dst.MeasurementRecordLength[2] = src.MeasurementRecordLength[0];
#else
    dst.MeasurementRecordLength[0] = src.MeasurementRecordLength[0];
    dst.MeasurementRecordLength[1] = src.MeasurementRecordLength[1];
    dst.MeasurementRecordLength[2] = src.MeasurementRecordLength[2];
#endif
}

struct PacketMeasurementsResponseVar // TODO all variable packets don't need
                                     // to be packed
{
    PacketMeasurementsResponseMin Min;
    nonce_array_32 Nonce = {0};
    std::vector<PacketMeasurementBlockVar> MeasurementBlockVector;
    std::vector<uint8_t> OpaqueDataVector;
    std::vector<uint8_t> SignatureVector;

    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_MEASUREMENTS;
    static constexpr bool sizeIsConstant = false;

    RetStat finalize()
    {
        uint32_t len = 0;
        len += std::accumulate(
            MeasurementBlockVector.begin(), MeasurementBlockVector.end(), 0,
            [](uint32_t a, const auto& iter) { return a + iter.getSize(); });
        if (!Min.setMeasurementRecordLength(len))
        {
            return RetStat::ERROR_UNKNOWN;
        }
        return RetStat::OK;
    }

    bool operator==(const PacketMeasurementsResponseVar& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        if (!isEqual(Nonce, other.Nonce))
        {
            return false;
        }
        if (MeasurementBlockVector != other.MeasurementBlockVector)
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
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_printMl(log, Min);
        SPDMCPP_LOG_iexprln(log, Nonce);

        SPDMCPP_LOG_iexprln(log, MeasurementBlockVector.size());
        for (size_t i = 0; i < MeasurementBlockVector.size(); ++i)
        {
            log.iprintln("MeasurementBlockVector[" + std::to_string(i) +
                         "]:"); // TODO something more optimal
            MeasurementBlockVector[i].printMl(log);
        }

        SPDMCPP_LOG_iexprln(log, OpaqueDataVector);
        SPDMCPP_LOG_iexprln(log, SignatureVector);
    }
};

[[nodiscard]] inline RetStat
    packetEncodeInternal(const PacketMeasurementsResponseVar& p,
                         std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetEncodeInternal(p.Min, buf, off);
    if (isError(rs))
    {
        return rs;
    }

    for (const auto& mb : p.MeasurementBlockVector)
    {
        rs = packetEncodeInternal(mb, buf, off);
        if (isError(rs))
        {
            {
                return rs;
            }
        }
    }
    packetEncodeBasic(p.Nonce, buf, off);

    packetEncodeBasic(static_cast<uint16_t>(p.OpaqueDataVector.size()), buf,
                      off); // TODO verify no greater than 1024

    packetEncodeBasic(p.OpaqueDataVector, buf, off);

    packetEncodeBasic(p.SignatureVector, buf, off);

    return rs;
}

[[nodiscard]] inline RetStat
    packetDecodeInternal(PacketMeasurementsResponseVar& p,
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

    {
        size_t end = off + p.Min.getMeasurementRecordLength();
        while (off < end)
        {
            p.MeasurementBlockVector.resize(p.MeasurementBlockVector.size() +
                                            1);
            rs =
                packetDecodeInternal(p.MeasurementBlockVector.back(), buf, off);
            if (isError(rs))
            {
                {
                    return rs;
                }
            }
        }
        if (off != end)
        {
            return RetStat::ERROR_UNKNOWN;
        }
    }
    rs = packetDecodeBasic(p.Nonce, buf, off);
    if (isError(rs))
    {
        {
            return rs;
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
    if (info.GetMeasurementsParam1 & 0x01)
    {
        p.SignatureVector.resize(info.SignatureSize);
        rs = packetDecodeBasic(p.SignatureVector, buf, off);
    }

    return rs;
}

#endif
