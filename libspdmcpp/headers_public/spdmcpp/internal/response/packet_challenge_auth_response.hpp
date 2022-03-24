
#include "../../packet.hpp"

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

    bool operator==(const packet_challenge_auth_response_min& other) const
    {
        return memcmp(this, &other, sizeof(other)) == 0;
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

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_CHALLENGE_AUTH;
    static constexpr bool size_is_constant = false;

    RetStat finalize()
    {
        return RetStat::OK;
    }

    bool operator==(const packet_challenge_auth_response_var& other) const
    {
        if (Min != other.Min)
        {
            return false;
        }
        if (memcmp(Nonce, other.Nonce, sizeof(Nonce)))
        {
            return false;
        }
        if (CertChainHashVector != other.CertChainHashVector)
        {
            return false;
        }
        if (MeasurementSummaryHashVector != other.MeasurementSummaryHashVector)
        {
            return false;
        }
        if (OpaqueDataVector != other.OpaqueDataVector)
        {
            return false;
        }
        if (SignatureVector != other.SignatureVector)
        {
            return false;
        }
        return true;
    }

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Min);
        log.iprint("Nonce[32]: ");
        log.println(Nonce, sizeof_array(Nonce));
        SPDMCPP_LOG_idataln(log, CertChainHashVector);
        SPDMCPP_LOG_idataln(log, MeasurementSummaryHashVector);
        SPDMCPP_LOG_idataln(log, OpaqueDataVector);
        SPDMCPP_LOG_idataln(log, SignatureVector);
    }
};

[[nodiscard]] inline RetStat
    packet_encode_internal(const packet_challenge_auth_response_var& p,
                           std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packet_encode_internal(p.Min, buf, off);
    if (is_error(rs))
        return rs;

    packet_encode_basic(p.CertChainHashVector, buf, off);

    packet_encode_basic(p.Nonce, buf, off);

    if (!p.MeasurementSummaryHashVector.empty())
    {
        packet_encode_basic(p.MeasurementSummaryHashVector, buf, off);
    }

    // TODO verify no greater than 1024
    packet_encode_basic(static_cast<uint16_t>(p.OpaqueDataVector.size()), buf,
                        off);
    packet_encode_basic(p.OpaqueDataVector, buf, off);

    packet_encode_basic(p.SignatureVector, buf, off);

    return rs;
}

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
    {
        uint16_t length = 0;
        rs = packet_decode_basic(length, buf,
                                 off); // TODO verify no greater than 1024
        if (is_error(rs))
            return rs;
        p.OpaqueDataVector.resize(length);
        rs = packet_decode_basic(p.OpaqueDataVector, buf, off);
        if (is_error(rs))
            return rs;
    }
    p.SignatureVector.resize(info.SignatureSize);
    rs = packet_decode_basic(p.SignatureVector, buf, off);
    return rs;
}
