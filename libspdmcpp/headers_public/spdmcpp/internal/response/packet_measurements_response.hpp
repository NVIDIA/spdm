
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
    bool set_measurement_record_length(uint32_t len)
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

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Header);
        SPDMCPP_LOG_iexprln(log, NumberOfBlocks);
        log.iprint("MeasurementRecordLength[3]: ");
        log.println(MeasurementRecordLength,
                    sizeof_array(MeasurementRecordLength));
    }

    bool operator==(const packet_measurements_response_min& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
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

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_MEASUREMENTS;
    static constexpr bool size_is_constant = false;

    RetStat finalize()
    {
        uint32_t len = 0;
        for (const auto& mb : MeasurementBlockVector)
        {
            len += mb.get_size();
        }
        if (!Min.set_measurement_record_length(len))
        {
            return RetStat::ERROR_UNKNOWN;
        }
        return RetStat::OK;
    }

    bool operator==(const packet_measurements_response_var& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        if (memcmp(Nonce, other.Nonce, sizeof(Nonce)))
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

        SPDMCPP_LOG_idataln(log, OpaqueDataVector);
        SPDMCPP_LOG_idataln(log, SignatureVector);
    }
};

[[nodiscard]] inline RetStat
    packet_encode_internal(const packet_measurements_response_var& p,
                           std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packet_encode_internal(p.Min, buf, off);
    if (is_error(rs))
    {
        return rs;
    }

    for (const auto& mb : p.MeasurementBlockVector)
    {
        rs = packet_encode_internal(mb, buf, off);
        if (is_error(rs))
            return rs;
    }
    packet_encode_basic(p.Nonce, buf, off);

    packet_encode_basic(static_cast<uint16_t>(p.OpaqueDataVector.size()), buf,
                        off); // TODO verify no greater than 1024

    packet_encode_basic(p.OpaqueDataVector, buf, off);

    packet_encode_basic(p.SignatureVector, buf, off);

    return rs;
}

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

    {
        uint16_t length = 0;
        rs = packet_decode_basic(length, buf,
                                 off); // TODO verify no greater than 1024
        if (is_error(rs))
            return rs;

        p.OpaqueDataVector.resize(length);
        rs = packet_decode_basic(p.OpaqueDataVector, buf, off);
        if (is_error(rs))
            return rs;
    }
    if (info.GetMeasurementsParam1 & 0x01)
    {
        p.SignatureVector.resize(info.SignatureSize);
        rs = packet_decode_basic(p.SignatureVector, buf, off);
    }

    return rs;
}
