
#pragma once

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

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Min);
        SPDMCPP_LOG_idataln(log, ValueVector);
    }
};

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
