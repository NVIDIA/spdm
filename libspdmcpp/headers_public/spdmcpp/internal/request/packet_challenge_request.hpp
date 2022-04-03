
#include "../../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct PacketChallengeRequest
{
    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);
    nonce_array_32 Nonce = {0};

    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::REQUEST_CHALLENGE;
    static constexpr bool sizeIsConstant = true;

    void printMl(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_printMl(log, Header);
        SPDMCPP_LOG_iexprln(log, Nonce);
    }
};

inline void endianHostSpdmCopy(const PacketChallengeRequest& src,
                               PacketChallengeRequest& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
    dst.Nonce = src.Nonce;
}

#endif
