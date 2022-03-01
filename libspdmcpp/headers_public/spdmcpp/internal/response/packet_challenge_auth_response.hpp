
#pragma once

struct packet_challenge_auth_response_min
{
    packet_message_header Header = packet_message_header(RequestResponseCode);

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_CHALLENGE_AUTH;
    static constexpr bool size_is_constant = true;

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Header);
    }
};

inline void endian_host_spdm_copy(const packet_challenge_auth_response_min& src,
                                  packet_challenge_auth_response_min& dst)
{
    endian_host_spdm_copy(src.Header, dst.Header);
}

struct packet_challenge_auth_response_var
{
    packet_challenge_auth_response_min Min;
    nonce_array_32 Nonce = {0};
    std::vector<uint8_t> CertChainHashVector;
    std::vector<uint8_t> MeasurementSummaryHashVector;
    std::vector<uint8_t> OpaqueDataVector;
    std::vector<uint8_t> SignatureVector;
    uint16_t OpaqueLength = 0;

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_CHALLENGE_AUTH;
    static constexpr bool size_is_constant = false;

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Min);
        log.iprint("Nonce[32]: ");
        log.println(Nonce, sizeof_array(Nonce));
        SPDMCPP_LOG_idataln(log, CertChainHashVector);
        SPDMCPP_LOG_idataln(log, MeasurementSummaryHashVector);
        SPDMCPP_LOG_iexprln(log, OpaqueLength);
        SPDMCPP_LOG_idataln(log, OpaqueDataVector);
        SPDMCPP_LOG_idataln(log, SignatureVector);
    }
};

[[nodiscard]] inline RetStat
    packet_decode_internal(packet_challenge_auth_response_var& p,
                           const std::vector<uint8_t>& buf, size_t& off,
                           const packet_decode_info& info)
{
    auto rs = packet_decode_internal(p.Min, buf, off);
    if (is_error(rs))
        return rs;

    p.CertChainHashVector.resize(info.BaseHashSize);
    rs = packet_decode_basic(p.CertChainHashVector, buf, off);
    if (is_error(rs))
        return rs;

    rs = packet_decode_basic(p.Nonce, buf, off);
    if (is_error(rs))
        return rs;

    if (info.ChallengeParam2)
    {
        p.MeasurementSummaryHashVector.resize(info.BaseHashSize);
        rs = packet_decode_basic(p.MeasurementSummaryHashVector, buf, off);
        if (is_error(rs))
            return rs;
    }
    rs = packet_decode_basic(p.OpaqueLength, buf,
                             off); // TODO verify no greater than 1024
    if (is_error(rs))
        return rs;
    p.OpaqueDataVector.resize(p.OpaqueLength);
    rs = packet_decode_basic(p.OpaqueDataVector, buf, off);
    if (is_error(rs))
        return rs;

    p.SignatureVector.resize(info.SignatureSize);
    rs = packet_decode_basic(p.SignatureVector, buf, off);
    return RetStat::OK;
}
