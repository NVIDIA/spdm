
#pragma once

struct packet_error_response_var
{
    packet_message_header Header = packet_message_header(RequestResponseCode);
    // TODO handle custom data

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_ERROR;
    static constexpr bool size_is_constant = false;

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
};

[[nodiscard]] inline RetStat
    packet_decode_internal(packet_error_response_var& p,
                           const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packet_decode_internal(p.Header, buf, off);
    // TODO handle custom data
    /*	p.VersionNumberEntries.resize(p.Min.VersionNumberEntryCount);
        for (size_t i = 0; i < p.VersionNumberEntries.size(); ++i) {
            buf = packet_decode_internal(p.VersionNumberEntries[i], buf);
        }*/
    return rs;
}
[[nodiscard]] inline RetStat
    packet_encode_internal(const packet_error_response_var& p,
                           std::vector<uint8_t>& buf, size_t& off)
{
    // TODO handle custom data
    auto rs = packet_encode_internal(p.Header, buf, off);
    return rs;
}
