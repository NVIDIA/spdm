
#include "../../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct packet_capabilities_response
{
    packet_message_header Header = packet_message_header(RequestResponseCode);
    uint8_t Reserved0 = 0;
    uint8_t CTExponent = 0;
    uint16_t Reserved1 = 0;
    ResponderCapabilitiesFlags Flags = ResponderCapabilitiesFlags::NIL;

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_CAPABILITIES;
    static constexpr bool size_is_constant = true;

    packet_capabilities_response() = default;
    packet_capabilities_response(uint8_t ct_exponent,
                                 ResponderCapabilitiesFlags flags) :
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

inline void endian_host_spdm_copy(const packet_capabilities_response& src,
                                  packet_capabilities_response& dst)
{
    endian_host_spdm_copy(src.Header, dst.Header);
    endian_host_spdm_copy(src.Reserved0, dst.Reserved0);
    endian_host_spdm_copy(src.CTExponent, dst.CTExponent);
    endian_host_spdm_copy(src.Reserved1, dst.Reserved1);
    endian_host_spdm_copy(src.Flags, dst.Flags);
}

#endif
