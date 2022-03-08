
#pragma once

struct packet_get_measurements_request_min
{
    packet_message_header Header = packet_message_header(RequestResponseCode);

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::REQUEST_GET_MEASUREMENTS;
    static constexpr bool size_is_constant = true;

    bool has_nonce() const
    {
        return Header.Param1 & 0x01;
    }
    void set_nonce()
    {
        Header.Param1 |= 0x01;
    }

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Header);
    }

    bool operator==(const packet_get_measurements_request_min& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void
    endian_host_spdm_copy(const packet_get_measurements_request_min& src,
                          packet_get_measurements_request_min& dst)
{
    endian_host_spdm_copy(src.Header, dst.Header);
}

struct packet_get_measurements_request_var
{
    packet_get_measurements_request_min Min;
    nonce_array_32 Nonce = {0};
    uint8_t SlotIDParam = 0;

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::REQUEST_GET_MEASUREMENTS;
    static constexpr bool size_is_constant = false;

    bool has_nonce() const
    {
        return Min.has_nonce();
    }
    void set_nonce()
    {
        Min.set_nonce();
    }

    uint16_t get_size() const
    {
        size_t size = 0;
        size += sizeof(Min);
        if (Min.has_nonce())
        {
            size += sizeof(Nonce);
            size += sizeof(SlotIDParam);
        }
        assert(size <= std::numeric_limits<uint16_t>::max());
        return static_cast<uint16_t>(size);
    }

    bool operator==(const packet_get_measurements_request_var& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        if (memcmp(Nonce, other.Nonce, sizeof(Nonce)))
        {
            return false;
        }
        if (SlotIDParam != other.SlotIDParam)
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
        SPDMCPP_LOG_iexprln(log, SlotIDParam);
    }
};

[[nodiscard]] inline RetStat
    packet_encode_internal(const packet_get_measurements_request_var& p,
                           std::vector<uint8_t>& buf, size_t& off)
{
    size_t size = p.get_size();
    buf.resize(off + size);

    auto rs = packet_encode_internal(p.Min, buf, off);
    if (is_error(rs))
        return rs;

    if (p.has_nonce())
    {
        packet_encode_basic(p.Nonce, buf, off);
        packet_encode_basic(p.SlotIDParam, buf, off);
    }
    return rs;
}

[[nodiscard]] inline RetStat
    packet_decode_internal(packet_get_measurements_request_var& p,
                           const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packet_decode_internal(p.Min, buf, off);
    if (is_error(rs))
        return rs;

    if (p.has_nonce())
    {
        rs = packet_decode_basic(p.Nonce, buf, off);
        if (is_error(rs))
            return rs;

        rs = packet_decode_basic(p.SlotIDParam, buf, off);
        if (is_error(rs))
            return rs;
    }

    return rs;
}
