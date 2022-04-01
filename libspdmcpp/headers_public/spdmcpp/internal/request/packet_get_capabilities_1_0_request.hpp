
#include "../../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct PacketGetCapabilities10Request
{
    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);

    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::REQUEST_GET_CAPABILITIES;
    static constexpr bool sizeIsConstant = true;

    void printMl(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_printMl(log, Header);
    }
};

inline void endianHostSpdmCopy(const PacketGetCapabilities10Request& src,
                               PacketGetCapabilities10Request& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
}

#endif
