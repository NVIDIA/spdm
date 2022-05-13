
#pragma once

#include "../../packet.hpp"

#ifdef SPDMCPP_PACKET_HPP

struct PacketReqAlgStruct
{
    AlgTypeEnum AlgType = AlgTypeEnum::UNKNOWN;
    uint8_t AlgCount = 0;

    // the sizes of these arrays are the maximum possible sizes according to
    // DSP0274_1.1.1 page 43
    std::array<uint8_t, 14> AlgSupported = {0};
    std::array<uint32_t, 15> AlgExternal = {0};

    static PacketReqAlgStruct
        buildAlgSupported(AlgTypeEnum type, uint8_t algsup0, uint8_t algsup1)
    {
        PacketReqAlgStruct ret;
        ret.AlgType = type;
        ret.setFixedAlgCount(2);
        ret.AlgSupported[0] = algsup0;
        ret.AlgSupported[1] = algsup1;
        return ret;
    }

    static PacketReqAlgStruct buildReqBaseAsymAlg(BaseAsymAlgoFlags flags)
    {
        PacketReqAlgStruct ret;
        ret.AlgType = AlgTypeEnum::ReqBaseAsymAlg;
        ret.setFixedAlgCount(2);
        ret.setReqBaseAsymAlg(flags);
        return ret;
    }

    void setFixedAlgCount(uint8_t count)
    {
        AlgCount &= ~0xF0; // mask out previous value
        AlgCount |= count << 4;
    }
    void setExtAlgCount(uint8_t count)
    {
        AlgCount &= ~0xF; // mask out previous value
        AlgCount |= count & 0xF;
    }
    uint8_t getFixedAlgCount() const
    {
        return AlgCount >> 4;
    }
    uint8_t getExtAlgCount() const
    {
        return AlgCount & 0xF;
    }

    uint16_t getSize() const
    {
        size_t size = 0;
        size += sizeof(AlgType);
        size += sizeof(AlgCount);
        size += getFixedAlgCount() * sizeof(AlgSupported[0]);
        size += getExtAlgCount() * sizeof(AlgExternal[0]);
        SPDMCPP_ASSERT(size <= std::numeric_limits<uint16_t>::max());
        return static_cast<uint16_t>(size);
    }

    BaseAsymAlgoFlags getReqBaseAsymAlg() const
    {
        return static_cast<BaseAsymAlgoFlags>(
            static_cast<uint16_t>(AlgSupported[0]) |
            static_cast<uint16_t>(AlgSupported[1]) << 16);
    }
    void setReqBaseAsymAlg(BaseAsymAlgoFlags flags)
    {
        auto bits = static_cast<std::underlying_type_t<BaseAsymAlgoFlags>>(flags);
        AlgSupported[0] = bits;
        AlgSupported[1] = (bits >> 16);
    }

    void print(LogClass& log) const
    {
        log.print("<");
        SPDMCPP_LOG_expr(log, AlgType);
        log.print("   FixedAlgCount: ");
        log.print(getFixedAlgCount());
        log.print("   ExtAlgCount: ");
        log.print(getExtAlgCount());

        switch (AlgType)
        {
            case AlgTypeEnum::ReqBaseAsymAlg:
                log.print("   ReqBaseAsymAlg: ");
                log.print(get_debug_string(getReqBaseAsymAlg()));
                break;
            default:
                log.print("   UNIMPLEMENTED");
                break;
        }
        log.print(">");
    }

    bool operator==(const PacketReqAlgStruct& other) const
    {
        // TODO should only compare the valid portion of AlgSupported,
        // AlgExternal?
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

[[nodiscard]] inline RetStat packetEncodeInternal(const PacketReqAlgStruct& p,
                                                  std::vector<uint8_t>& buf,
                                                  size_t& start)
{
    size_t off = start;
    buf.resize(start + p.getSize());
    packetEncodeBasic(p.AlgType, buf, off);
    packetEncodeBasic(p.AlgCount, buf, off);
    for (uint8_t i = 0; i < p.getFixedAlgCount(); ++i)
    {
        packetEncodeBasic(p.AlgSupported[i], buf, off);
    }
    for (uint8_t i = 0; i < p.getExtAlgCount(); ++i)
    {
        packetEncodeBasic(p.AlgExternal[i], buf, off);
    }
    start = off;
    return RetStat::OK;
}
[[nodiscard]] inline RetStat
    packetDecodeInternal(PacketReqAlgStruct& p, const std::vector<uint8_t>& buf,
                         size_t& off)
{
    auto rs = packetDecodeBasic(p.AlgType, buf, off);
    if (isError(rs))
    {
        {
            return rs;
        }
    }
    rs = packetDecodeBasic(p.AlgCount, buf, off);
    if (isError(rs))
    {
        {
            return rs;
        }
    }
    // TODO validate p.AlgType & Count?
    for (uint8_t i = 0; i < p.getFixedAlgCount(); ++i)
    {
        rs = packetDecodeBasic(p.AlgSupported[i], buf, off);
        if (isError(rs))
        {
            {
                return rs;
            }
        }
    }
    for (uint8_t i = 0; i < p.getExtAlgCount(); ++i)
    {
        rs = packetDecodeBasic(p.AlgExternal[i], buf, off);
        if (isError(rs))
        {
            {
                return rs;
            }
        }
    }
    return RetStat::OK;
}

struct PacketNegotiateAlgorithmsRequestMin
{
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::REQUEST_NEGOTIATE_ALGORITHMS;
    static constexpr bool sizeIsConstant = true;

    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);
    uint16_t Length = 0;
    uint8_t MeasurementSpecification = 0;
    uint8_t Reserved0 = 0;
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
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_printMl(log, Header);
        SPDMCPP_LOG_iexprln(log, Length);
        SPDMCPP_LOG_iexprln(log, MeasurementSpecification);
        SPDMCPP_LOG_iexprln(log, Reserved0);
        SPDMCPP_LOG_iflagsln(log, BaseAsymAlgo);
        SPDMCPP_LOG_iflagsln(log, BaseHashAlgo);
        SPDMCPP_LOG_iexprln(log, Reserved1);
        SPDMCPP_LOG_iexprln(log, Reserved2);
        SPDMCPP_LOG_iexprln(log, Reserved3);
        SPDMCPP_LOG_iexprln(log, ExtAsymCount);
        SPDMCPP_LOG_iexprln(log, ExtHashCount);
        SPDMCPP_LOG_iexprln(log, Reserved4);
    }

    bool operator==(const PacketNegotiateAlgorithmsRequestMin& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endianHostSpdmCopy(const PacketNegotiateAlgorithmsRequestMin& src,
                               PacketNegotiateAlgorithmsRequestMin& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
    endianHostSpdmCopy(src.Length, dst.Length);
    endianHostSpdmCopy(src.MeasurementSpecification,
                       dst.MeasurementSpecification);
    endianHostSpdmCopy(src.Reserved0, dst.Reserved0);
    endianHostSpdmCopy(src.BaseAsymAlgo, dst.BaseAsymAlgo);
    endianHostSpdmCopy(src.BaseHashAlgo, dst.BaseHashAlgo);
    endianHostSpdmCopy(src.Reserved1, dst.Reserved1);
    endianHostSpdmCopy(src.Reserved2, dst.Reserved2);
    endianHostSpdmCopy(src.Reserved3, dst.Reserved3);
    endianHostSpdmCopy(src.ExtAsymCount, dst.ExtAsymCount);
    endianHostSpdmCopy(src.ExtHashCount, dst.ExtHashCount);
    endianHostSpdmCopy(src.Reserved4, dst.Reserved4);
}

struct PacketNegotiateAlgorithmsRequestVar
{
    PacketNegotiateAlgorithmsRequestMin Min;

    std::vector<PacketReqAlgStruct> PacketReqAlgVector;

    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::REQUEST_NEGOTIATE_ALGORITHMS;
    static constexpr bool sizeIsConstant = false;

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

    bool operator==(const PacketNegotiateAlgorithmsRequestVar& other) const
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

        SPDMCPP_LOG_iexprln(
            log, PacketReqAlgVector.size()); // TODO template for vector?!
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
    packetEncodeInternal(const PacketNegotiateAlgorithmsRequestVar& p,
                         std::vector<uint8_t>& buf, size_t& off)
{
    buf.resize(off + p.Min.Length);
    auto rs = packetEncodeInternal(p.Min, buf, off);

    // TODO HANDLE ExtAsymCount and ExtHashCount!!!

    for (const auto& iter : p.PacketReqAlgVector)
    {
        rs = packetEncodeInternal(iter, buf, off);
        if (isError(rs))
        {
            {
                return rs;
            }
        }
    }
    return rs;
}

[[nodiscard]] inline RetStat
    packetDecodeInternal(PacketNegotiateAlgorithmsRequestVar& p,
                         const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetDecodeInternal(p.Min, buf, off);

    // TODO HANDLE ExtAsymCount and ExtHashCount!!!

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
