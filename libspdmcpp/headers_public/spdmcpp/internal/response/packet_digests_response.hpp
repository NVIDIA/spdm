
#pragma once

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
};
inline void endian_host_spdm_copy(const packet_digests_response_min& src,
                                  packet_digests_response_min& dst)
{
    endian_host_spdm_copy(src.Header, dst.Header);
}

struct packet_hash_sha_386 // TODO the hash size is not fixed!!!
{
    uint8_t Value[48];
    static constexpr bool size_is_constant = true;

    void print(LogClass& log) const
    {
        log.print(Value, sizeof_array(Value));
    }
};

struct packet_digests_response_var
{
    packet_digests_response_min Min;
    std::vector<std::vector<uint8_t>>
        DigestVector; // TODO the hash size is not fixed!!!

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_DIGESTS;
    static constexpr bool size_is_constant = false;

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Min);
        SPDMCPP_LOG_iexprln(log, DigestVector.size());
        for (size_t i = 0; i < DigestVector.size(); ++i)
        {
            log.iprint("DigestVector[" + std::to_string(i) +
                       "]: "); // TODO something more optimal
            log.print(DigestVector[i].data(), DigestVector[i].size());
            log.endl();
        }
    }
};

[[nodiscard]] inline RetStat
    packet_decode_internal(packet_digests_response_var& p,
                           const std::vector<uint8_t>& buf, size_t& off,
                           const packet_decode_info& info)
{
    auto rs = packet_decode_internal(p.Min, buf, off);
    if (is_error(rs))
        return rs;

    p.DigestVector.resize(count_bits(
        p.Min.Header.Param2)); // TODO check size for reasonable limit!!
    for (size_t i = 0; i < p.DigestVector.size(); ++i)
    {
        p.DigestVector[i].resize(info.BaseHashSize);
        rs = packet_decode_basic(p.DigestVector[i], buf, off);
        if (is_error(rs))
            return rs;
    }
    return RetStat::OK;
}
