
#include "../../packet.hpp"

#pragma once

struct packet_challenge_request
{
    packet_message_header Header = packet_message_header(RequestResponseCode);
    nonce_array_32 Nonce = {0};

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::REQUEST_CHALLENGE;
    static constexpr bool size_is_constant = true;

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Header);
        log.iprint("Nonce[32]: ");
        log.println(Nonce, sizeof_array(Nonce));
    }
};

inline void endian_host_spdm_copy(const packet_challenge_request& src,
                                  packet_challenge_request& dst)
{
    endian_host_spdm_copy(src.Header, dst.Header);
    memcpy(dst.Nonce, src.Nonce, sizeof(dst.Nonce));
}
