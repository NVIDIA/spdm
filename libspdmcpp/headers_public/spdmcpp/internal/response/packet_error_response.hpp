
#include "../../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct PacketErrorResponseMin
{
    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);

    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_ERROR;
    static constexpr bool sizeIsConstant = true;

    void print(LogClass& log) const
    {
        Header.print(log);
        // TODO handle custom data
    }

    void printMl(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_printMl(log, Header);
    }

    bool operator==(const PacketErrorResponseMin& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endianHostSpdmCopy(const PacketErrorResponseMin& src,
                               PacketErrorResponseMin& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
}

struct PacketErrorResponseVar
{
    PacketErrorResponseMin Min;
    // TODO handle custom data

    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_ERROR;
    static constexpr bool sizeIsConstant = false;

    bool operator==(const PacketErrorResponseVar& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        return true;
    }

    void printMl(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_printMl(log, Min);
    }
};

[[nodiscard]] inline RetStat
    packetDecodeInternal(PacketErrorResponseVar& p,
                         const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetDecodeInternal(p.Min, buf, off);
    // TODO handle custom data
    return rs;
}
[[nodiscard]] inline RetStat
    packetEncodeInternal(const PacketErrorResponseVar& p,
                         std::vector<uint8_t>& buf, size_t& off)
{
    // TODO handle custom data
    auto rs = packetEncodeInternal(p.Min, buf, off);
    return rs;
}

#endif
