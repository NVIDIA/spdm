
#pragma once

struct packet_certificate_response_min
{
    packet_message_header Header = packet_message_header(RequestResponseCode);
    uint16_t PortionLength = 0;
    uint16_t RemainderLength = 0;

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_CERTIFICATE;
    static constexpr bool size_is_constant = true;

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Header);
        SPDMCPP_LOG_iexprln(log, PortionLength);
        SPDMCPP_LOG_iexprln(log, RemainderLength);
    }
};

inline void endian_host_spdm_copy(const packet_certificate_response_min& src,
                                  packet_certificate_response_min& dst)
{
    endian_host_spdm_copy(src.Header, dst.Header);
    endian_host_spdm_copy(src.PortionLength, dst.PortionLength);
    endian_host_spdm_copy(src.RemainderLength, dst.RemainderLength);
}

struct packet_certificate_response_var
{
    packet_certificate_response_min Min;
    std::vector<uint8_t> CertificateVector;

    static constexpr RequestResponseEnum RequestResponseCode =
        RequestResponseEnum::RESPONSE_CERTIFICATE;
    static constexpr bool size_is_constant = false;

    void print_ml(LogClass& log) const
    {
        SPDMCPP_LOG_INDENT(log);
        SPDMCPP_LOG_print_ml(log, Min);
        SPDMCPP_LOG_iexprln(log, CertificateVector.size());
        if (!CertificateVector.empty())
            SPDMCPP_LOG_idataln(log, CertificateVector);
    }
};

[[nodiscard]] inline RetStat
    packet_decode_internal(packet_certificate_response_var& p,
                           const std::vector<uint8_t>& buf, size_t& off)
{
    auto rs = packet_decode_internal(p.Min, buf, off);
    if (is_error(rs))
        return rs;

    p.CertificateVector.resize(p.Min.PortionLength);
    memcpy(p.CertificateVector.data(), &buf[off], p.CertificateVector.size());
    off += p.CertificateVector.size();

    return RetStat::OK;
}
