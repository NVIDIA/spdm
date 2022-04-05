
#include "../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct PacketMessageHeader
{
    MessageVersionEnum MessageVersion = MessageVersionEnum::SPDM_1_0;
    RequestResponseEnum requestResponseCode = RequestResponseEnum::INVALID;
    uint8_t Param1 = 0;
    uint8_t Param2 = 0;

    static constexpr bool sizeIsConstant = true;

    PacketMessageHeader() = default;
    PacketMessageHeader(RequestResponseEnum rr) : requestResponseCode(rr)
    {}
    PacketMessageHeader(MessageVersionEnum v, RequestResponseEnum rr) :
        MessageVersion(v), requestResponseCode(rr)
    {}

    void print(LogClass& log) const
    {
        log.print('<');
        SPDMCPP_LOG_expr(log, MessageVersion);
        log.print("   ");
        SPDMCPP_LOG_expr(log, requestResponseCode);
        log.print("   ");
        SPDMCPP_LOG_expr(log, Param1);
        log.print("   ");
        SPDMCPP_LOG_expr(log, Param2);
        log.print(">");
    }
    void printMl(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_iexprln(log, MessageVersion);
        SPDMCPP_LOG_iexprln(log, requestResponseCode);
        SPDMCPP_LOG_iexprln(log, Param1);
        SPDMCPP_LOG_iexprln(log, Param2);
    }
};

// TODO there's this magic template library for iterating over members... it'd
// be really convenient to use it!!!

[[nodiscard]] inline MessageVersionEnum
    packetMessageHeaderGetVersion(const uint8_t* buf)
{
    auto& p = *reinterpret_cast<const PacketMessageHeader*>(buf);
    SPDMCPP_STATIC_ASSERT(sizeof(p.requestResponseCode) == 1);
    return p.MessageVersion;
}
[[nodiscard]] inline RequestResponseEnum
    packetMessageHeaderGetRequestresponsecode(const uint8_t* buf)
{
    auto& p = *reinterpret_cast<const PacketMessageHeader*>(buf);
    SPDMCPP_STATIC_ASSERT(sizeof(p.requestResponseCode) == 1);
    return p.requestResponseCode;
}
inline void
    packetMessageHeaderSetRequestresponsecode(uint8_t* buf,
                                              RequestResponseEnum rrcode)
{
    auto& p = *reinterpret_cast<PacketMessageHeader*>(buf);
    SPDMCPP_STATIC_ASSERT(sizeof(p.requestResponseCode) == 1);
    p.requestResponseCode = rrcode;
}
/*	inline void endian_swap(packet_message_header& p)//TODO decide, likely not
   needed?
    {
        endian_swap(p.spdm_version);
        endian_swap(p.requestResponseCode);
        endian_swap(p.param1);
        endian_swap(p.param2);
    }*/
/*	inline void endian_host_spdm_swap(packet_message_header& p)//TODO decide,
   likely not needed?
    {
        endian_host_spdm_swap(p.spdm_version);
        endian_host_spdm_swap(p.requestResponseCode);
        endian_host_spdm_swap(p.param1);
        endian_host_spdm_swap(p.param2);
    }*/
inline void endianHostSpdmCopy(const PacketMessageHeader& src,
                               PacketMessageHeader& dst)
{
    endianHostSpdmCopy(src.MessageVersion, dst.MessageVersion);
    endianHostSpdmCopy(src.requestResponseCode, dst.requestResponseCode);
    endianHostSpdmCopy(src.Param1, dst.Param1);
    endianHostSpdmCopy(src.Param2, dst.Param2);
}

#endif
