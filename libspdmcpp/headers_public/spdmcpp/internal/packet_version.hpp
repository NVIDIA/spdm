
#include "../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct PacketVersionNumber // TODO bitfields are ill-defined endianness-wise
                           // iirc!?
{
    uint16_t Alpha : 4;
    uint16_t UpdateVersionNumber : 4;
    uint16_t MinorVersion : 4;
    uint16_t MajorVersion : 4;

    static constexpr bool sizeIsConstant = true;
    PacketVersionNumber()
    {
        MajorVersion = 0;
        MinorVersion = 0;
        UpdateVersionNumber = 0;
        Alpha = 0;
    }
    MessageVersionEnum getMessageVersion() const
    {
        switch (MajorVersion)
        {
            case 1:
                switch (MinorVersion)
                {
                    case 0:
                        return MessageVersionEnum::SPDM_1_0;
                    case 1:
                        return MessageVersionEnum::SPDM_1_1;
                }
        }
        return MessageVersionEnum::UNKNOWN;
    }

    void print(LogClass& log) const
    {
        log.print("<");
        SPDMCPP_LOG_expr(log, MajorVersion);
        log.print("   ");
        SPDMCPP_LOG_expr(log, MinorVersion);
        log.print("   ");
        SPDMCPP_LOG_expr(log, UpdateVersionNumber);
        log.print("   ");
        SPDMCPP_LOG_expr(log, Alpha);
        log.print(">");
    }

    bool operator==(const PacketVersionNumber& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endianHostSpdmCopy(const PacketVersionNumber& src,
                               PacketVersionNumber& dst)
{
    dst = src; // TODO surely wrong
}

#endif
