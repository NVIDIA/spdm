
#include "../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct packet_certificate_chain
{
    uint16_t Length = 0;
    uint16_t Reserved = 0;

    static constexpr bool size_is_constant = true;

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

inline void endian_host_spdm_copy(const packet_certificate_chain& src,
                                  packet_certificate_chain& dst)
{
    endian_host_spdm_copy(src.Length, dst.Length);
    dst.Reserved = src.Reserved;
}

#endif
