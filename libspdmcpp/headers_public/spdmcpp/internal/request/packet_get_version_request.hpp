
#include "../../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct PacketGetVersionRequest
{
    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::REQUEST_GET_VERSION;
    static constexpr bool sizeIsConstant = true;

    void printMl(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_printMl(log, Header);
    }
};

inline void endianHostSpdmCopy(const PacketGetVersionRequest& src,
                               PacketGetVersionRequest& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
}

#endif
