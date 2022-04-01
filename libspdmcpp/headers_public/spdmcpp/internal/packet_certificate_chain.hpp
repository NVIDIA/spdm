
#include "../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct PacketCertificateChain
{
    uint16_t Length = 0;
    uint16_t Reserved = 0;

    static constexpr bool sizeIsConstant = true;

    void print(LogClass& log) const
    {
        log.print("<");
        SPDMCPP_LOG_expr(log, Length);
        log.print("   ");
        SPDMCPP_LOG_expr(log, Reserved);
        log.print("   ");
        log.print(">");
    }
};

inline void endianHostSpdmCopy(const PacketCertificateChain& src,
                               PacketCertificateChain& dst)
{
    endianHostSpdmCopy(src.Length, dst.Length);
    dst.Reserved = src.Reserved;
}

#endif
