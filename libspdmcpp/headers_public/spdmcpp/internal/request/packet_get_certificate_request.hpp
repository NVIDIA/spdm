
#include "../../packet.hpp"

#pragma once

struct packet_get_certificate_request
{
    packet_message_header Header = packet_message_header(RequestResponseCode);
    uint16_t Offset = 0;
    uint16_t Length = 0;

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::REQUEST_GET_CERTIFICATE;
    static constexpr bool size_is_constant = true;

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Header);
        SPDMCPP_LOG_iexprln(log, Offset);
        SPDMCPP_LOG_iexprln(log, Length);
    }
};

inline void endian_host_spdm_copy(const packet_get_certificate_request& src,
                                  packet_get_certificate_request& dst)
{
    endian_host_spdm_copy(src.Header, dst.Header);
    endian_host_spdm_copy(src.Offset, dst.Offset);
    endian_host_spdm_copy(src.Length, dst.Length);
}
