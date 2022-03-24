
#include "../../packet.hpp"

#pragma once

struct packet_get_digests_request
{
    packet_message_header Header = packet_message_header(RequestResponseCode);

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::REQUEST_GET_DIGESTS;
    static constexpr bool size_is_constant = true;

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Header);
    }
};

inline void endian_host_spdm_copy(const packet_get_digests_request& src,
                                  packet_get_digests_request& dst)
{
    endian_host_spdm_copy(src.Header, dst.Header);
}
