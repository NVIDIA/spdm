
#pragma once

struct packet_error_response_min
{
    packet_message_header Header = packet_message_header(RequestResponseCode);

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_ERROR;
    static constexpr bool size_is_constant = true;

    void print(LogClass& log) const
    {
        Header.print(log);
        // TODO handle custom data
    }

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Header);
    }

    bool operator==(const packet_error_response_min& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endian_host_spdm_copy(const packet_error_response_min& src,
                                  packet_error_response_min& dst)
{
    endian_host_spdm_copy(src.Header, dst.Header);
}

struct packet_error_response_var
{
    packet_error_response_min Min;
    // TODO handle custom data

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_ERROR;
    static constexpr bool size_is_constant =
        false; // TODO decide how we need/want to handle such packets

    bool operator==(const packet_error_response_var& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        return true;
    }

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Min);
    }
};

[[nodiscard]] inline RetStat
    packet_decode_internal(packet_error_response_var& p,
                           const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packet_decode_internal(p.Min, buf, off);
    // TODO handle custom data
    return rs;
}
[[nodiscard]] inline RetStat
    packet_encode_internal(const packet_error_response_var& p,
                           std::vector<uint8_t>& buf, size_t& off)
{
    // TODO handle custom data
    auto rs = packet_encode_internal(p.Min, buf, off);
    return rs;
}
