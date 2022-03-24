
#include "../../packet.hpp"

#pragma once

struct packet_get_capabilities_request
{
    packet_message_header Header = packet_message_header(RequestResponseCode);
    uint8_t Reserved0 = 0;
    uint8_t CTExponent = 0;
    uint16_t Reserved1 = 0;
    RequesterCapabilitiesFlags Flags = RequesterCapabilitiesFlags::NIL;

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::REQUEST_GET_CAPABILITIES;
    static constexpr bool size_is_constant = true;

    packet_get_capabilities_request() = default;
    packet_get_capabilities_request(uint8_t ct_exponent,
                                    RequesterCapabilitiesFlags flags) :
        CTExponent(ct_exponent),
        Flags(flags)
    {}

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Header);
        SPDMCPP_LOG_iexprln(log, Reserved0);
        SPDMCPP_LOG_iexprln(log, CTExponent);
        SPDMCPP_LOG_iexprln(log, Reserved1);
        SPDMCPP_LOG_iflagsln(log, Flags);
    }
};

inline void endian_host_spdm_copy(const packet_get_capabilities_request& src,
                                  packet_get_capabilities_request& dst)
{
    endian_host_spdm_copy(src.Header, dst.Header);
    dst.Reserved0 = src.Reserved0;
    endian_host_spdm_copy(src.CTExponent, dst.CTExponent);
    dst.Reserved1 = src.Reserved1;
    endian_host_spdm_copy(src.Flags, dst.Flags);
}
