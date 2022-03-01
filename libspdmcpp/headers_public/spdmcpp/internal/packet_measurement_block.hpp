
#pragma once

struct packet_measurement_block_min
{
    uint8_t Index = 0;
    uint8_t MeasurementSpecification = 0; // TODO enum?
    uint16_t MeasurementSize = 0;

    static constexpr bool size_is_constant = true;

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_iexprln(log, Index);
        log.print("   ");
        SPDMCPP_LOG_iexprln(log, MeasurementSpecification);
        log.print("   ");
        SPDMCPP_LOG_iexprln(log, MeasurementSize);
        log.print("   ");
    }
};

inline void endian_host_spdm_copy(const packet_measurement_block_min& src,
                                  packet_measurement_block_min& dst)
{
    endian_host_spdm_copy(src.Index, dst.Index);
    endian_host_spdm_copy(src.MeasurementSpecification,
                          dst.MeasurementSpecification);
    endian_host_spdm_copy(src.MeasurementSize, dst.MeasurementSize);
}

struct packet_measurement_block_var
{
    packet_measurement_block_min Min;
    std::vector<uint8_t> MeasurementVector;

    static constexpr bool size_is_constant = false;

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Min);
        SPDMCPP_LOG_idataln(log, MeasurementVector);
    }
};

[[nodiscard]] inline RetStat
    packet_decode_internal(packet_measurement_block_var& p,
                           const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packet_decode_basic(p.Min, buf, off);
    if (is_error(rs))
        return rs;

    p.MeasurementVector.resize(p.Min.MeasurementSize);
    rs = packet_decode_basic(p.MeasurementVector, buf, off);
    return rs;
}
