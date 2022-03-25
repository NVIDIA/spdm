
#pragma once

struct PacketReqAlgStruct
{
    AlgTypeEnum AlgType = AlgTypeEnum::UNKNOWN;
    uint8_t AlgCount = 0;
    uint8_t AlgSupported[14] = {0}; // TODO is this really the limit?
    uint32_t AlgExternal[15] = {0}; // TODO is this really is the limit?

    // 		static constexpr bool size_is_constant = false;
    static PacketReqAlgStruct buildSupported2(AlgTypeEnum type, uint8_t algsup0,
                                              uint8_t algsup1)
    {
        PacketReqAlgStruct ret;
        ret.AlgType = type;
        ret.setFixedAlgCount(2);
        ret.AlgSupported[0] = algsup0;
        ret.AlgSupported[1] = algsup1;
        return ret;
    }

    void setFixedAlgCount(uint8_t count)
    {
        AlgCount &= 0xF0;
        AlgCount |= count << 4;
    }
    void setExtAlgCount(uint8_t count)
    {
        AlgCount &= 0xF;
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
    // TODO need many more helpers?!

    uint16_t get_size() const
    {
        size_t size = 0;
        size += sizeof(AlgType);
        size += sizeof(AlgCount);
        size += getFixedAlgCount() * sizeof(AlgSupported[0]);
        size += getExtAlgCount() * sizeof(AlgExternal[0]);
        assert(size <= std::numeric_limits<uint16_t>::max());
        return static_cast<uint16_t>(size);
    }

    void print(LogClass& log) const
    {
        log.print("<");
        SPDMCPP_LOG_expr(log, AlgType);
        log.print("   ");
        SPDMCPP_LOG_expr(log, AlgCount);
        log.print("   ");
        //	SPDMCPP_LOG_expr(log, AlgSupported);
        // TODO support printing
        log.print(">");
    }

    bool operator==(const PacketReqAlgStruct& other) const
    {
        // TODO should only compare the valid portion of AlgSupported,
        // AlgExternal?
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

[[nodiscard]] inline RetStat packet_encode_internal(const PacketReqAlgStruct& p,
                                                    std::vector<uint8_t>& buf,
                                                    size_t& start)
{
    size_t off = start;
    buf.resize(start + p.get_size());
    packet_encode_basic(p.AlgType, buf, off);
    packet_encode_basic(p.AlgCount, buf, off);
    for (uint8_t i = 0; i < p.getFixedAlgCount(); ++i)
    {
        packet_encode_basic(p.AlgSupported[i], buf, off);
    }
    for (uint8_t i = 0; i < p.getExtAlgCount(); ++i)
    {
        packet_encode_basic(p.AlgExternal[i], buf, off);
    }
    start = off;
    return RetStat::OK;
}
[[nodiscard]] inline RetStat
    packet_decode_internal(PacketReqAlgStruct& p,
                           const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packet_decode_basic(p.AlgType, buf, off);
    if (is_error(rs))
        return rs;
    rs = packet_decode_basic(p.AlgCount, buf, off);
    if (is_error(rs))
        return rs;
    // TODO validate p.AlgType & Count?
    for (uint8_t i = 0; i < p.getFixedAlgCount(); ++i)
    {
        rs = packet_decode_basic(p.AlgSupported[i], buf, off);
        if (is_error(rs))
            return rs;
    }
    for (uint8_t i = 0; i < p.getExtAlgCount(); ++i)
    {
        rs = packet_decode_basic(p.AlgExternal[i], buf, off);
        if (is_error(rs))
            return rs;
    }
    return RetStat::OK;
}

struct packet_negotiate_algorithms_request_min
{
    packet_message_header Header = packet_message_header(RequestResponseCode);
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

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::REQUEST_NEGOTIATE_ALGORITHMS;
    static constexpr bool size_is_constant = true;

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Header);
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

    bool operator==(const packet_negotiate_algorithms_request_min& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void
    endian_host_spdm_copy(const packet_negotiate_algorithms_request_min& src,
                          packet_negotiate_algorithms_request_min& dst)
{
    endian_host_spdm_copy(src.Header, dst.Header);
    endian_host_spdm_copy(src.Length, dst.Length);
    endian_host_spdm_copy(src.MeasurementSpecification,
                          dst.MeasurementSpecification);
    dst.Reserved0 = src.Reserved0;
    endian_host_spdm_copy(src.BaseAsymAlgo, dst.BaseAsymAlgo);
    endian_host_spdm_copy(src.BaseHashAlgo, dst.BaseHashAlgo);
    dst.Reserved1 = src.Reserved1;
    dst.Reserved2 = src.Reserved2;
    dst.Reserved3 = src.Reserved3;
    endian_host_spdm_copy(src.ExtAsymCount, dst.ExtAsymCount);
    endian_host_spdm_copy(src.ExtHashCount, dst.ExtHashCount);
    dst.Reserved4 = src.Reserved4;
}

struct packet_negotiate_algorithms_request_var
{
    typedef packet_negotiate_algorithms_request_min MinType;
    MinType Min;

    std::vector<PacketReqAlgStruct> PacketReqAlgVector;

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::REQUEST_NEGOTIATE_ALGORITHMS;
    static constexpr bool size_is_constant = false;

    uint16_t get_size() const
    {
        size_t size = 0;
        size += sizeof(Min);
        for (const auto& iter : PacketReqAlgVector)
        {
            size += iter.get_size();
        }
        assert(size <= std::numeric_limits<uint16_t>::max());
        return static_cast<uint16_t>(size);
    }
    RetStat finalize()
    {
        if (PacketReqAlgVector.size() >= 256)
        {
            return RetStat::ERROR_UNKNOWN;
        }
        Min.Header.Param1 = static_cast<uint8_t>(PacketReqAlgVector.size());
        Min.Length = get_size();
        return RetStat::OK;
    }

    bool operator==(const packet_negotiate_algorithms_request_var& other) const
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

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Min);

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
    packet_encode_internal(const packet_negotiate_algorithms_request_var& p,
                           std::vector<uint8_t>& buf, size_t& off)
{
    buf.resize(off + p.Min.Length);
    auto rs = packet_encode_internal(p.Min, buf, off);

    // TODO HANDLE ExtAsymCount and ExtHashCount!!!

    for (const auto& iter : p.PacketReqAlgVector)
    {
        rs = packet_encode_internal(iter, buf, off);
        if (is_error(rs))
            return rs;
    }
    return rs;
}

[[nodiscard]] inline RetStat
    packet_decode_internal(packet_negotiate_algorithms_request_var& p,
                           const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packet_decode_internal(p.Min, buf, off);

    // TODO HANDLE ExtAsymCount and ExtHashCount!!!

    p.PacketReqAlgVector.resize(p.Min.Header.Param1);
    for (size_t i = 0; i < p.PacketReqAlgVector.size(); ++i)
    {
        rs = packet_decode_internal(p.PacketReqAlgVector[i], buf, off);
        if (is_error(rs))
        {
            return rs;
        }
    }
    return rs;
}
