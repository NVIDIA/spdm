
#include "../../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct PacketVersionResponseMin
{
    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);
    uint8_t Reserved = 0;
    //    uint8_t VersionNumberEntryCount = 0;

    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_VERSION;
    static constexpr bool sizeIsConstant =
        true; // TODO decide how we need/want to handle such packets

    void printMl(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_printMl(log, Header);
        SPDMCPP_LOG_iexprln(log, Reserved);
        // SPDMCPP_LOG_iexprln(log, VersionNumberEntryCount);
    }

    bool operator==(const PacketVersionResponseMin& other) const
    {
        // TODO should only compare the valid portion of AlgSupported,
        // AlgExternal?
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endianHostSpdmCopy(const PacketVersionResponseMin& src,
                               PacketVersionResponseMin& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
    dst.Reserved = src.Reserved;
    // endianHostSpdmCopy(src.VersionNumberEntryCount,
    //   dst.VersionNumberEntryCount);
}

struct PacketVersionResponseVar
{
    PacketVersionResponseMin Min;
    std::vector<PacketVersionNumber> VersionNumberEntries;

    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::RESPONSE_VERSION;
    static constexpr bool sizeIsConstant =
        false; // TODO decide how we need/want to handle such packets

    void printMl(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_printMl(log, Min);

        for (size_t i = 0; i < VersionNumberEntries.size(); ++i)
        {
            log.iprint("VersionNumberEntries[" + std::to_string(i) +
                       "]: "); // TODO something more optimal
            VersionNumberEntries[i].print(log);
            log.endl();
        }
    }

    bool operator==(const PacketVersionResponseVar& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        if (VersionNumberEntries != other.VersionNumberEntries)
        {
            return false;
        }
        return true;
    }
};

[[nodiscard]] inline RetStat
    packetDecodeInternal(PacketVersionResponseVar& p,
                         const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetDecodeInternal(p.Min, buf, off);
    if (rs != RetStat::OK)
    {
        return rs;
    }
    {
        uint8_t size = 0;
        rs = packetDecodeBasic(size, buf, off);
        if (rs != RetStat::OK)
        {
            return rs;
        }
        p.VersionNumberEntries.resize(size);
    }
    // p.VersionNumberEntries.resize(p.Min.VersionNumberEntryCount);
    for (size_t i = 0; i < p.VersionNumberEntries.size(); ++i)
    {
        rs = packetDecodeInternal(p.VersionNumberEntries[i], buf, off);
        if (rs != RetStat::OK)
        {
            return rs;
        }
    }
    return RetStat::OK;
}

[[nodiscard]] inline RetStat
    packetEncodeInternal(const PacketVersionResponseVar& p,
                         std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetEncodeInternal(p.Min, buf, off);
    if (rs != RetStat::OK)
    {
        return rs;
    }

    {
        uint8_t size = p.VersionNumberEntries.size();
        packetEncodeBasic(size, buf, off);
    }
    for (size_t i = 0; i < p.VersionNumberEntries.size(); ++i)
    {
        rs = packetEncodeInternal(p.VersionNumberEntries[i], buf, off);
        if (rs != RetStat::OK)
        {
            return rs;
        }
    }
    return RetStat::OK;
}

#endif
