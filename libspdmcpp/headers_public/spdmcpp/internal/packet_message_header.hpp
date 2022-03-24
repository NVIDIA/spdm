
#include "../packet.hpp"

#pragma once

struct packet_message_header
{
    MessageVersionEnum MessageVersion = MessageVersionEnum::SPDM_1_0;
    RequestResponseEnum RequestResponseCode = RequestResponseEnum::INVALID;
    uint8_t Param1 = 0;
    uint8_t Param2 = 0;

    static constexpr bool size_is_constant = true;

    packet_message_header() = default;
    packet_message_header(RequestResponseEnum rr) : RequestResponseCode(rr)
    {}
    packet_message_header(MessageVersionEnum v, RequestResponseEnum rr) :
        MessageVersion(v), RequestResponseCode(rr)
    {}

    void print(LogClass& log) const
    {
        log.print('<');
        SPDMCPP_LOG_expr(log, MessageVersion);
        log.print("   ");
        SPDMCPP_LOG_expr(log, RequestResponseCode);
        log.print("   ");
        SPDMCPP_LOG_expr(log, Param1);
        log.print("   ");
        SPDMCPP_LOG_expr(log, Param2);
        log.print(">");
    }
    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_iexprln(log, MessageVersion);
        SPDMCPP_LOG_iexprln(log, RequestResponseCode);
        SPDMCPP_LOG_iexprln(log, Param1);
        SPDMCPP_LOG_iexprln(log, Param2);
    }
};

// TODO there's this magic template library for iterating over members... it'd
// be really convenient to use it!!!

[[nodiscard]] inline MessageVersionEnum
    packet_message_header_get_version(const uint8_t* buf)
{
    auto& p = *reinterpret_cast<const packet_message_header*>(buf);
    static_assert(sizeof(p.RequestResponseCode) == 1);
    return p.MessageVersion;
}
[[nodiscard]] inline RequestResponseEnum
    packet_message_header_get_requestresponsecode(const uint8_t* buf)
{
    auto& p = *reinterpret_cast<const packet_message_header*>(buf);
    static_assert(sizeof(p.RequestResponseCode) == 1);
    return p.RequestResponseCode;
}
inline void
    packet_message_header_set_requestresponsecode(uint8_t* buf,
                                                  RequestResponseEnum rrcode)
{
    auto& p = *reinterpret_cast<packet_message_header*>(buf);
    static_assert(sizeof(p.RequestResponseCode) == 1);
    p.RequestResponseCode = rrcode;
}
/*	inline void endian_swap(packet_message_header& p)//TODO decide, likely not
   needed?
    {
        endian_swap(p.spdm_version);
        endian_swap(p.RequestResponseCode);
        endian_swap(p.param1);
        endian_swap(p.param2);
    }*/
/*	inline void endian_host_spdm_swap(packet_message_header& p)//TODO decide,
   likely not needed?
    {
        endian_host_spdm_swap(p.spdm_version);
        endian_host_spdm_swap(p.RequestResponseCode);
        endian_host_spdm_swap(p.param1);
        endian_host_spdm_swap(p.param2);
    }*/
inline void endian_host_spdm_copy(const packet_message_header& src,
                                  packet_message_header& dst)
{
    endian_host_spdm_copy(src.MessageVersion, dst.MessageVersion);
    endian_host_spdm_copy(src.RequestResponseCode, dst.RequestResponseCode);
    endian_host_spdm_copy(src.Param1, dst.Param1);
    endian_host_spdm_copy(src.Param2, dst.Param2);
}
