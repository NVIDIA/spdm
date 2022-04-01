
#include "../../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct PacketCapabilitiesResponse
{
    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);
    uint8_t Reserved0 = 0;
    uint8_t CTExponent = 0;
    uint16_t Reserved1 = 0;
    ResponderCapabilitiesFlags Flags = ResponderCapabilitiesFlags::NIL;

    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_CAPABILITIES;
    static constexpr bool sizeIsConstant = true;

    PacketCapabilitiesResponse() = default;
    PacketCapabilitiesResponse(uint8_t ctExponent,
                               ResponderCapabilitiesFlags flags) :
        CTExponent(ctExponent),
        Flags(flags)
    {}

    void printMl(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_printMl(log, Header);
        SPDMCPP_LOG_iexprln(log, Reserved0);
        SPDMCPP_LOG_iexprln(log, CTExponent);
        SPDMCPP_LOG_iexprln(log, Reserved1);
        SPDMCPP_LOG_iflagsln(log, Flags);
    }
};

inline void endianHostSpdmCopy(const PacketCapabilitiesResponse& src,
                               PacketCapabilitiesResponse& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
    endianHostSpdmCopy(src.Reserved0, dst.Reserved0);
    endianHostSpdmCopy(src.CTExponent, dst.CTExponent);
    endianHostSpdmCopy(src.Reserved1, dst.Reserved1);
    endianHostSpdmCopy(src.Flags, dst.Flags);
}

#endif
