
#include "../../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct PacketAlgorithmsResponseMin
{
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

    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_ALGORITHMS;
    static constexpr bool sizeIsConstant =
        true; // TODO decide how we need/want to handle such packets

    void printMl(LogClass& log) const
    {
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
    dst.Reserved0 = src.Reserved0;
    endianHostSpdmCopy(src.MeasurementHashAlgo, dst.MeasurementHashAlgo);
    endianHostSpdmCopy(src.BaseAsymAlgo, dst.BaseAsymAlgo);
    endianHostSpdmCopy(src.BaseHashAlgo, dst.BaseHashAlgo);
    dst.Reserved1 = src.Reserved1;
    dst.Reserved2 = src.Reserved2;
    dst.Reserved3 = src.Reserved3;
    endianHostSpdmCopy(src.ExtAsymCount, dst.ExtAsymCount);
    endianHostSpdmCopy(src.ExtHashCount, dst.ExtHashCount);
    dst.Reserved4 = src.Reserved4;
}

struct PacketAlgorithmsResponseVar
{
    PacketAlgorithmsResponseMin Min;
    std::vector<PacketReqAlgStruct> PacketReqAlgVector;

    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_ALGORITHMS;
    static constexpr bool sizeIsConstant =
        false; // TODO decide how we need/want to handle such packets

    uint16_t getSize() const
    {
        size_t size = 0;
        size += sizeof(Min);
        size += std::accumulate(PacketReqAlgVector.begin(), PacketReqAlgVector.end(), 0, [](size_t a, const auto& iter) { return a + iter.getSize(); } );
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
    packetDecodeInternal(PacketAlgorithmsResponseVar& p,
                         const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetDecodeInternal(p.Min, buf, off);
    if (isError(rs))
    {
        {
            return rs;
        }
    }

    p.PacketReqAlgVector.resize(p.Min.Header.Param1);
    for (auto& iter : p.PacketReqAlgVector)
    {
        rs = packetDecodeInternal(iter, buf, off);
        if (isError(rs))
        {
            return rs;
        }
    }
    return rs;
}

#endif
