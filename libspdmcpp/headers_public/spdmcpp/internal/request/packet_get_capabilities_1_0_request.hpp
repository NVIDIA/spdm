
#include "../../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct packet_get_capabilities_1_0_request
{
    packet_message_header Header = packet_message_header(RequestResponseCode);

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::REQUEST_GET_CAPABILITIES;
    static constexpr bool size_is_constant = true;

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Header);
    }
};

inline void
    endian_host_spdm_copy(const packet_get_capabilities_1_0_request& src,
                          packet_get_capabilities_1_0_request& dst)
{
    endian_host_spdm_copy(src.Header, dst.Header);
}

#endif
