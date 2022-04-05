
#include "../../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct PacketDigestsResponseMin
{
    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);

    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_DIGESTS;
    static constexpr bool sizeIsConstant = true;

    void printMl(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_printMl(log, Header);
    }

    bool operator==(const PacketDigestsResponseMin& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endianHostSpdmCopy(const PacketDigestsResponseMin& src,
                               PacketDigestsResponseMin& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
}

struct PacketDigestsResponseVar
{
    PacketDigestsResponseMin Min;

    static constexpr uint8_t digestsNum = 8;
    std::array<std::vector<uint8_t>, digestsNum> Digests;

    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_DIGESTS;
    static constexpr bool sizeIsConstant = false;

    RetStat finalize()
    {
        Min.Header.Param2 = 0;
        for (uint8_t i = 0; i < digestsNum; ++i)
        {
            if (!Digests[i].empty())
            {
                Min.Header.Param2 |= 1 << i;
            }
        }
        return RetStat::OK;
    }

    bool operator==(const PacketDigestsResponseVar& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        for (uint8_t i = 0; i < digestsNum; ++i)
        {
            if (Digests[i] != other.Digests[i])
            {
                return false;
            }
        }
        return true;
    }

    void printMl(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_printMl(log, Min);
        for (uint8_t i = 0; i < digestsNum; ++i)
        {
            log.iprint("Digests[" + std::to_string(i) +
                       "]: "); // TODO something more optimal
            log.print(Digests[i].data(), Digests[i].size());
            log.endl();
        }
    }
};

[[nodiscard]] inline RetStat
    packetEncodeInternal(const PacketDigestsResponseVar& p,
                         std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetEncodeInternal(p.Min, buf, off);

    for (uint8_t i = 0; i < PacketDigestsResponseVar::digestsNum; ++i)
    {
        if ((1 << i) & p.Min.Header.Param2)
        {
            packetEncodeBasic(p.Digests[i], buf, off);
        }
    }
    return rs;
}

[[nodiscard]] inline RetStat
    packetDecodeInternal(PacketDigestsResponseVar& p,
                         const std::vector<uint8_t>& buf, size_t& off,
                         const PacketDecodeInfo& info)
{
    auto rs = packetDecodeInternal(p.Min, buf, off);
    if (isError(rs))
    {
        {
            return rs;
        }
    }

    //     p.Digests.resize(countBits(
    //         p.Min.Header.Param2)); // TODO check size for reasonable limit!!
    for (uint8_t i = 0; i < PacketDigestsResponseVar::digestsNum; ++i)
    {
        if ((1 << i) & p.Min.Header.Param2)
        {
            p.Digests[i].resize(info.BaseHashSize);
            rs = packetDecodeBasic(p.Digests[i], buf, off);
            if (isError(rs))
            {
                return rs;
            }
        }
    }
    return RetStat::OK;
}

#endif
