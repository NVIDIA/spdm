
#pragma once

struct packet_get_version_response_min
{
    packet_message_header Header = packet_message_header(RequestResponseCode);
    uint8_t Reserved = 0;
    //    uint8_t VersionNumberEntryCount = 0;

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_VERSION;
    static constexpr bool size_is_constant =
        true; // TODO decide how we need/want to handle such packets

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Header);
        SPDMCPP_LOG_iexprln(log, Reserved);
        // SPDMCPP_LOG_iexprln(log, VersionNumberEntryCount);
    }
};

inline void endian_host_spdm_copy(const packet_get_version_response_min& src,
                                  packet_get_version_response_min& dst)
{
    endian_host_spdm_copy(src.Header, dst.Header);
    dst.Reserved = src.Reserved;
    // endian_host_spdm_copy(src.VersionNumberEntryCount,
    //   dst.VersionNumberEntryCount);
}

struct packet_get_version_response_var
{
    packet_get_version_response_min Min;
    std::vector<packet_version_number> VersionNumberEntries;

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_VERSION;
    static constexpr bool size_is_constant =
        false; // TODO decide how we need/want to handle such packets

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Min);

        for (size_t i = 0; i < VersionNumberEntries.size(); ++i)
        {
            log.iprint("VersionNumberEntries[" + std::to_string(i) +
                       "]: "); // TODO something more optimal
            VersionNumberEntries[i].print(log);
            log.endl();
        }
    }
};

[[nodiscard]] inline RetStat
    packet_decode_internal(packet_get_version_response_var& p,
                           const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packet_decode_internal(p.Min, buf, off);
    if (rs != RetStat::OK)
    {
        return rs;
    }
    {
        uint8_t size = 0;
        rs = packet_decode_basic(size, buf, off);
        if (rs != RetStat::OK)
        {
            return rs;
        }
        p.VersionNumberEntries.resize(size);
    }
    // p.VersionNumberEntries.resize(p.Min.VersionNumberEntryCount);
    for (size_t i = 0; i < p.VersionNumberEntries.size(); ++i)
    {
        rs = packet_decode_internal(p.VersionNumberEntries[i], buf, off);
        if (rs != RetStat::OK)
        {
            return rs;
        }
    }
    return RetStat::OK;
}
