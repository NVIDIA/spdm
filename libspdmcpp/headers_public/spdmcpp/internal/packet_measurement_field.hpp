
#include "../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct packet_measurement_field_min
{
    uint8_t Type = 0;
    uint16_t Size = 0;

    static constexpr bool size_is_constant = true;

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_iexprln(log, Type);
        log.print("   ");
    }

    bool operator==(const packet_measurement_field_min& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endian_host_spdm_copy(const packet_measurement_field_min& src,
                                  packet_measurement_field_min& dst)
{
    endian_host_spdm_copy(src.Type, dst.Type);
    endian_host_spdm_copy(src.Size, dst.Size);
}

struct packet_measurement_field_var
{
    packet_measurement_field_min Min;
    std::vector<uint8_t> ValueVector;

    static constexpr bool size_is_constant = false;

    RetStat finalize()
    {
        if (ValueVector.size() >= std::numeric_limits<uint16_t>::max())
        {
            return RetStat::ERROR_UNKNOWN;
        }
        Min.Size = static_cast<uint16_t>(ValueVector.size());
        return RetStat::OK;
    }

    bool operator==(const packet_measurement_field_var& other) const
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

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Min);
        SPDMCPP_LOG_idataln(log, ValueVector);
    }
};

[[nodiscard]] inline RetStat
    packet_encode_internal(const packet_measurement_field_var& p,
                           std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packet_encode_internal(p.Min, buf, off);
    if (is_error(rs))
    {
        return rs;
    }
    packet_encode_basic(p.ValueVector, buf, off);
    return rs;
}

[[nodiscard]] inline RetStat
    packet_decode_internal(packet_measurement_field_var& p,
                           const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packet_decode_basic(p.Min, buf, off);
    if (is_error(rs))
        return rs;

    p.ValueVector.resize(p.Min.Size);
    rs = packet_decode_basic(p.ValueVector, buf, off);
    return rs;
}

#endif
