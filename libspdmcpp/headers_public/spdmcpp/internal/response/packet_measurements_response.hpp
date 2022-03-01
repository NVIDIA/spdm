
#pragma once

struct packet_measurements_response_min
{
    packet_message_header Header = packet_message_header(RequestResponseCode);
    uint8_t NumberOfBlocks = 0;
    uint8_t MeasurementRecordLength[3] = {0, 0, 0}; // wtf dmtf...

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_MEASUREMENTS;
    static constexpr bool size_is_constant = true;

    uint32_t get_measurement_record_length() const
    {
        return MeasurementRecordLength[0] | MeasurementRecordLength[1] << 8 |
               MeasurementRecordLength[2] << 16;
    }
    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Header);
        SPDMCPP_LOG_iexprln(log, NumberOfBlocks);
        log.iprint("MeasurementRecordLength[3]: ");
        log.println(MeasurementRecordLength,
                    sizeof_array(MeasurementRecordLength));
    }
};

inline void endian_host_spdm_copy(const packet_measurements_response_min& src,
                                  packet_measurements_response_min& dst)
{
    endian_host_spdm_copy(src.Header, dst.Header);
    endian_host_spdm_copy(src.NumberOfBlocks, dst.NumberOfBlocks);
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

struct packet_measurements_response_var // TODO all variable packets don't need
                                        // to be packed
{
    packet_measurements_response_min Min;
    nonce_array_32 Nonce = {0};
    std::vector<packet_measurement_block_var> MeasurementBlockVector;
    std::vector<uint8_t> OpaqueDataVector;
    std::vector<uint8_t> SignatureVector;
    uint16_t OpaqueLength = 0;

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_MEASUREMENTS;
    static constexpr bool size_is_constant = false;

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Min);
        log.iprint("Nonce[32]: ");
        log.println(Nonce, sizeof_array(Nonce));

        SPDMCPP_LOG_iexprln(log, MeasurementBlockVector.size());
        for (size_t i = 0; i < MeasurementBlockVector.size(); ++i)
        {
            log.iprintln("MeasurementBlockVector[" + std::to_string(i) +
                         "]:"); // TODO something more optimal
            MeasurementBlockVector[i].print_ml(log);
        }

        SPDMCPP_LOG_iexprln(log, OpaqueLength);
        SPDMCPP_LOG_idataln(log, OpaqueDataVector);
        SPDMCPP_LOG_idataln(log, SignatureVector);
    }
};

[[nodiscard]] inline RetStat
    packet_decode_internal(packet_measurements_response_var& p,
                           const std::vector<uint8_t>& buf, size_t& off,
                           const packet_decode_info& info)
{
    auto rs = packet_decode_internal(p.Min, buf, off);
    if (is_error(rs))
        return rs;

    {
        size_t end = off + p.Min.get_measurement_record_length();
        while (off < end)
        {
            p.MeasurementBlockVector.resize(p.MeasurementBlockVector.size() +
                                            1);
            rs = packet_decode_internal(p.MeasurementBlockVector.back(), buf,
                                        off);
            if (is_error(rs))
                return rs;
        }
        if (off != end)
        {
            assert(false); // TODO remove
            return RetStat::ERROR_UNKNOWN;
        }
    }
    rs = packet_decode_basic(p.Nonce, buf, off);
    if (is_error(rs))
        return rs;

    rs = packet_decode_basic(p.OpaqueLength, buf,
                             off); // TODO verify no greater than 1024
    if (is_error(rs))
        return rs;

    p.OpaqueDataVector.resize(p.OpaqueLength);
    rs = packet_decode_basic(p.OpaqueDataVector, buf, off);
    if (is_error(rs))
        return rs;

    if (info.GetMeasurementsParam1 & 0x01)
    {
        p.SignatureVector.resize(info.SignatureSize);
        rs = packet_decode_basic(p.SignatureVector, buf, off);
    }

    return rs;
}
