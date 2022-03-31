
#include "../../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct packet_digests_response_min
{
    packet_message_header Header = packet_message_header(RequestResponseCode);

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_DIGESTS;
    static constexpr bool size_is_constant = true;

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Header);
    }

    bool operator==(const packet_digests_response_min& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
    }
};

inline void endian_host_spdm_copy(const packet_digests_response_min& src,
                                  packet_digests_response_min& dst)
{
    endian_host_spdm_copy(src.Header, dst.Header);
}

struct packet_digests_response_var
{
    packet_digests_response_min Min;

    static constexpr uint8_t DIGESTS_NUM = 8;
    std::vector<uint8_t> Digests[DIGESTS_NUM];

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_DIGESTS;
    static constexpr bool size_is_constant = false;

    RetStat finalize()
    {
        Min.Header.Param2 = 0;
        for (uint8_t i = 0; i < DIGESTS_NUM; ++i)
        {
            if (!Digests[i].empty())
            {
                Min.Header.Param2 |= 1 << i;
            }
        }
        return RetStat::OK;
    }

    bool operator==(const packet_digests_response_var& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        for (uint8_t i = 0; i < DIGESTS_NUM; ++i)
        {
            if (Digests[i] != other.Digests[i])
            {
                return false;
            }
        }
        return true;
    }

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Min);
        for (uint8_t i = 0; i < DIGESTS_NUM; ++i)
        {
            log.iprint("Digests[" + std::to_string(i) +
                       "]: "); // TODO something more optimal
            log.print(Digests[i].data(), Digests[i].size());
            log.endl();
        }
    }
};

[[nodiscard]] inline RetStat
    packet_encode_internal(const packet_digests_response_var& p,
                           std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packet_encode_internal(p.Min, buf, off);

    for (uint8_t i = 0; i < packet_digests_response_var::DIGESTS_NUM; ++i)
    {
        if ((1 << i) & p.Min.Header.Param2)
        {
            packet_encode_basic(p.Digests[i], buf, off);
        }
    }
    return rs;
}

[[nodiscard]] inline RetStat
    packet_decode_internal(packet_digests_response_var& p,
                           const std::vector<uint8_t>& buf, size_t& off,
                           const packet_decode_info& info)
{
    auto rs = packet_decode_internal(p.Min, buf, off);
    if (is_error(rs))
        return rs;

    //     p.Digests.resize(count_bits(
    //         p.Min.Header.Param2)); // TODO check size for reasonable limit!!
    for (uint8_t i = 0; i < packet_digests_response_var::DIGESTS_NUM; ++i)
    {
        if ((1 << i) & p.Min.Header.Param2)
        {
            p.Digests[i].resize(info.BaseHashSize);
            rs = packet_decode_basic(p.Digests[i], buf, off);
            if (is_error(rs))
            {
                return rs;
            }
        }
    }
    return RetStat::OK;
}

#endif
