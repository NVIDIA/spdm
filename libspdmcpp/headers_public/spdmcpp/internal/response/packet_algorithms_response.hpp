
#include "../../packet.hpp"

#pragma once

struct packet_algorithms_response_min
{
    packet_message_header Header = packet_message_header(RequestResponseCode);
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

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_ALGORITHMS;
    static constexpr bool size_is_constant =
        true; // TODO decide how we need/want to handle such packets

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Header);
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

    bool operator==(const packet_algorithms_response_min& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endian_host_spdm_copy(const packet_algorithms_response_min& src,
                                  packet_algorithms_response_min& dst)
{
    endian_host_spdm_copy(src.Header, dst.Header);
    endian_host_spdm_copy(src.Length, dst.Length);
    endian_host_spdm_copy(src.MeasurementSpecification,
                          dst.MeasurementSpecification);
    dst.Reserved0 = src.Reserved0;
    endian_host_spdm_copy(src.MeasurementHashAlgo, dst.MeasurementHashAlgo);
    endian_host_spdm_copy(src.BaseAsymAlgo, dst.BaseAsymAlgo);
    endian_host_spdm_copy(src.BaseHashAlgo, dst.BaseHashAlgo);
    dst.Reserved1 = src.Reserved1;
    dst.Reserved2 = src.Reserved2;
    dst.Reserved3 = src.Reserved3;
    endian_host_spdm_copy(src.ExtAsymCount, dst.ExtAsymCount);
    endian_host_spdm_copy(src.ExtHashCount, dst.ExtHashCount);
    dst.Reserved4 = src.Reserved4;
}

struct packet_algorithms_response_var
{
    packet_algorithms_response_min Min;
    std::vector<PacketReqAlgStruct> PacketReqAlgVector;

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_ALGORITHMS;
    static constexpr bool size_is_constant =
        false; // TODO decide how we need/want to handle such packets

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

    bool operator==(const packet_algorithms_response_var& other) const
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
    packet_encode_internal(const packet_algorithms_response_var& p,
                           std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packet_encode_internal(p.Min, buf, off);
    if (is_error(rs))
    {
        return rs;
    }

    for (const auto& iter : p.PacketReqAlgVector)
    {
        rs = packet_encode_internal(iter, buf, off);
        if (is_error(rs))
        {
            return rs;
        }
    }
    return rs;
}

[[nodiscard]] inline RetStat
    packet_decode_internal(packet_algorithms_response_var& p,
                           const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packet_decode_internal(p.Min, buf, off);
    if (is_error(rs))
        return rs;

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
