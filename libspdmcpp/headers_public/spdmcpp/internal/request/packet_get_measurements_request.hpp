
#include "../../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct PacketGetMeasurementsRequestMin
{
    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);

    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::REQUEST_GET_MEASUREMENTS;
    static constexpr bool sizeIsConstant = true;

    bool hasNonce() const
    {
        return Header.Param1 & 0x01;
    }
    void setNonce()
    {
        Header.Param1 |= 0x01;
    }

    void printMl(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_printMl(log, Header);
    }

    bool operator==(const PacketGetMeasurementsRequestMin& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endianHostSpdmCopy(const PacketGetMeasurementsRequestMin& src,
                               PacketGetMeasurementsRequestMin& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
}

struct PacketGetMeasurementsRequestVar
{
    PacketGetMeasurementsRequestMin Min;
    nonce_array_32 Nonce = {0};
    uint8_t SlotIDParam = 0;

    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::REQUEST_GET_MEASUREMENTS;
    static constexpr bool sizeIsConstant = false;

    bool hasNonce() const
    {
        return Min.hasNonce();
    }
    void setNonce()
    {
        Min.setNonce();
    }

    uint16_t getSize() const
    {
        size_t size = 0;
        size += sizeof(Min);
        if (Min.hasNonce())
        {
            size += sizeof(Nonce);
            if (Min.Header.MessageVersion != MessageVersionEnum::SPDM_1_0)
            {
                size += sizeof(SlotIDParam);
            }
        }
        assert(size <= std::numeric_limits<uint16_t>::max());
        return static_cast<uint16_t>(size);
    }

    bool operator==(const PacketGetMeasurementsRequestVar& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }

        if (!isEqual(Nonce, other.Nonce))
        {
            return false;
        }
        if (SlotIDParam != other.SlotIDParam)
        {
            return false;
        }
        return true;
    }

    void printMl(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_printMl(log, Min);
        SPDMCPP_LOG_iexprln(log, Nonce);
        SPDMCPP_LOG_iexprln(log, SlotIDParam);
    }
};

[[nodiscard]] inline RetStat
    packetEncodeInternal(const PacketGetMeasurementsRequestVar& p,
                         std::vector<uint8_t>& buf, size_t& off)
{
    size_t size = p.getSize();
    buf.resize(off + size);

    auto rs = packetEncodeInternal(p.Min, buf, off);
    if (isError(rs))
    {
        {
            return rs;
        }
    }

    if (p.hasNonce())
    {
        packetEncodeBasic(p.Nonce, buf, off);
        if (p.Min.Header.MessageVersion != MessageVersionEnum::SPDM_1_0)
        {
            packetEncodeBasic(p.SlotIDParam, buf, off);
        }
    }
    return rs;
}

[[nodiscard]] inline RetStat
    packetDecodeInternal(PacketGetMeasurementsRequestVar& p,
                         const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packetDecodeInternal(p.Min, buf, off);
    if (isError(rs))
    {
        {
            return rs;
        }
    }

    if (p.hasNonce())
    {
        rs = packetDecodeBasic(p.Nonce, buf, off);
        if (isError(rs))
        {
            {
                return rs;
            }
        }

        if (p.Min.Header.MessageVersion != MessageVersionEnum::SPDM_1_0)
        {
            rs = packetDecodeBasic(p.SlotIDParam, buf, off);
            if (isError(rs))
            {
                {
                    return rs;
                }
            }
        }
    }

    return rs;
}

#endif
