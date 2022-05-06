
#include "../../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct PacketGetCapabilitiesRequest
{
    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);
    uint8_t Reserved0 = 0;
    uint8_t CTExponent = 0;
    uint16_t Reserved1 = 0;
    RequesterCapabilitiesFlags Flags = RequesterCapabilitiesFlags::NIL;

    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::REQUEST_GET_CAPABILITIES;
    static constexpr bool sizeIsConstant = true;

    PacketGetCapabilitiesRequest() = default;
    PacketGetCapabilitiesRequest(uint8_t ctExponent,
                                 RequesterCapabilitiesFlags flags) :
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

inline void endianHostSpdmCopy(const PacketGetCapabilitiesRequest& src,
                               PacketGetCapabilitiesRequest& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
    endianHostSpdmCopy(src.Reserved0, dst.Reserved0);
    endianHostSpdmCopy(src.CTExponent, dst.CTExponent);
    endianHostSpdmCopy(src.Reserved1, dst.Reserved1);
    endianHostSpdmCopy(src.Flags, dst.Flags);
}

#endif
