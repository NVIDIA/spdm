
#include <mbedtls/ecdh.h>
#include <mbedtls/error.h>
#include <mbedtls/pem.h>

#include <spdmcpp/connection.hpp>
#include <spdmcpp/connection_inl.hpp>
#include <spdmcpp/context.hpp>
#include <spdmcpp/helpers.hpp>
#include <spdmcpp/mbedtls_support.hpp>

#include <algorithm>
#include <fstream>

char err_msg[64]; // TODO remove! not thread safe

#define SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs)                                 \
    do                                                                         \
    {                                                                          \
        SPDMCPP_LOG_TRACE_RS(Log, (rs));                                       \
        if (is_error(rs))                                                      \
            return rs;                                                         \
    } while (false)

namespace spdmcpp
{

RetStat ConnectionClass::init_connection()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    HashM1M2.setup(HashEnum::SHA_384);
    CertificateSlotIdx = 0;
    fill_random(MeasurementNonce);

    auto rs = try_get_version();
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

RetStat ConnectionClass::refresh_measurements(SlotIdx slotidx)
{
    CertificateSlotIdx = slotidx;
    fill_random(MeasurementNonce);
    return refresh_measurements_internal();
}
RetStat ConnectionClass::refresh_measurements(SlotIdx slotidx,
                                              nonce_array_32& nonce)
{
    CertificateSlotIdx = slotidx;
    memcpy(MeasurementNonce, nonce, sizeof(MeasurementNonce));
    return refresh_measurements_internal();
}
RetStat ConnectionClass::refresh_measurements_internal()
{
    auto rs = try_get_version();
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

void ConnectionClass::reset_connection()
{
    clear_timeout();

    GotInfo = 0;
    CertificateSlotIdx = SLOT_NUM;
    MessageVersion = MessageVersionEnum::UNKNOWN;
    WaitingForResponse = RequestResponseEnum::INVALID;
    Algorithms = packet_algorithms_response_var();
    PacketDecodeInfo = packet_decode_info();
    SupportedVersions.clear();
    for (auto& s : Slots)
        s.clear();

    for (auto& b : Bufs)
        b.clear();
}

bool ConnectionClass::getCertificatesDER(std::vector<uint8_t>& buf,
                                         uint8_t slotidx) const
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    buf.clear();

    if (!SlotHasInfo(slotidx, SlotInfoEnum::CERTIFICATES))
        return false;

    const SlotClass& slot = Slots[slotidx];
#if 1
    if (slot.CertificateOffset == 0 ||
        slot.CertificateOffset >= slot.Certificates.size())
    {
        return false;
    }
    buf.resize(slot.Certificates.size() - slot.CertificateOffset);
    memcpy(buf.data(), slot.Certificates.data() + slot.CertificateOffset,
           buf.size());
    return true;
#else
    if (auto cert = slot.GetLeafCert())
    {
        buf.resize(cert->raw.len);
        memcpy(buf.data(), cert->raw.p, cert->raw.len);
        /*size_t size = 0x1000;
        buf.resize(size);
        int ret = mbedtls_x509write_crt_der(cert, buf.data(), size, nullptr,
        nullptr);	str.resize(off + cert->raw.len);*/
        return true;
    }
    return false;
#endif
}

#if 0
bool ConnectionClass::getCertificatesPEM(
    std::string& str, uint8_t slotidx) const // TODO change for slotidx
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    if (!HasInfo(ConnectionInfoEnum::CERTIFICATES))
        return false;

    str.clear();

    const SlotClass& slot = Slots[slotidx];
    if (!slot.Valid)
        return false;

    if (auto cert = slot.GetLeafCert())
    {
        size_t off = str.size();
        size_t size = 1024;
        str.resize(off + size);
        int ret = mbedtls_pem_write_buffer(
            "", "", (const unsigned char*)cert->raw.p, cert->raw.len,
            (unsigned char*)str.data() + off, size, &size);
        assert(ret == 0); // TODO make it robust
        str.resize(off + size);
        return true;
    }
    return false;
}
#endif

RetStat ConnectionClass::try_get_version()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    // assert(MessageVersion == MessageVersionEnum::UNKNOWN);

    for (auto& b : Bufs)
        b.clear();

    packet_get_version_request spdm_request;
    auto rs =
        send_request_setup_response(spdm_request, packet_version_response_var(),
                                    BufEnum::A, Timings.getT1());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handle_recv<packet_version_response_var>()
{
    packet_version_response_var resp;
    auto rs = interpret_response(resp);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    if (resp.Min.Header.MessageVersion != MessageVersionEnum::SPDM_1_0)
    {
        return RetStat::ERROR_INVALID_HEADER_VERSION; // TODO generalize
    }

    // TODO a lot more checks?
    std::swap(SupportedVersions, resp.VersionNumberEntries);
    MarkInfo(ConnectionInfoEnum::SUPPORTED_VERSIONS);

    AppendRecvToBuf(BufEnum::A);

    rs = choose_version();
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    Log.iprint("chosen MessageVersion: ");
    Log.println(MessageVersion);

    rs = try_get_capabilities();
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

RetStat ConnectionClass::choose_version()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    assert(HasInfo(ConnectionInfoEnum::SUPPORTED_VERSIONS));
    // assert(MessageVersion == MessageVersionEnum::UNKNOWN);

    std::vector<MessageVersionEnum> vers; // TODO is using just the enum fine or
                                          // do we need more detailed info?!
    vers.reserve(SupportedVersions.size());
    for (auto iter : SupportedVersions)
    {
        MessageVersionEnum e = iter.getMessageVersion();
        if (e != MessageVersionEnum::UNKNOWN)
        {
            vers.push_back(e);
        }
    }
    std::sort(vers.begin(), vers.end(), std::greater());

    for (auto ours : Context->get_supported_versions())
    {
        for (auto theirs : vers)
        {
            if (ours == theirs)
            {
                MessageVersion = theirs;
                MarkInfo(ConnectionInfoEnum::CHOOSEN_VERSION);
                return RetStat::OK;
            }
            else if (theirs < ours)
            {
                break;
            }
        }
    }
    return RetStat::ERROR_UNSUPPORTED_SPDM_VERSION;
}

RetStat ConnectionClass::try_get_capabilities()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    assert(HasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));

    packet_get_capabilities_request request;
    request.Header.MessageVersion = MessageVersion;
    // 			request.Flags = RequesterCapabilitiesFlags::CERT_CAP |
    // RequesterCapabilitiesFlags::CHAL_CAP |
    // RequesterCapabilitiesFlags::ENCRYPT_CAP |
    // RequesterCapabilitiesFlags::MAC_CAP;
    request.Flags = RequesterCapabilitiesFlags::CHAL_CAP;
    /*	request.Flags |= RequesterCapabilitiesFlags::ENCRYPT_CAP |
    RequesterCapabilitiesFlags::MAC_CAP;
    //	request.Flags |= RequesterCapabilitiesFlags::MUT_AUTH_CAP;
        request.Flags |= RequesterCapabilitiesFlags::KEY_EX_CAP;
        request.Flags |= RequesterCapabilitiesFlags::PSK_CAP_01;
        request.Flags |= RequesterCapabilitiesFlags::ENCAP_CAP;
        request.Flags |= RequesterCapabilitiesFlags::HBEAT_CAP;
        request.Flags |= RequesterCapabilitiesFlags::KEY_UPD_CAP;
        request.Flags |= RequesterCapabilitiesFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        */
    auto rs = send_request_setup_response(
        request, packet_capabilities_response(), BufEnum::A, Timings.getT1());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handle_recv<packet_capabilities_response>()
{
    packet_capabilities_response resp;
    auto rs = interpret_response(resp);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    MarkInfo(ConnectionInfoEnum::CAPABILITIES);
    AppendRecvToBuf(BufEnum::A);

    // TODO verify more stuff here especially flags !!!
    Timings.setCTExponent(resp.CTExponent);

    rs = try_negotiate_algorithms();
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

RetStat ConnectionClass::try_negotiate_algorithms()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    assert(HasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));
    assert(HasInfo(ConnectionInfoEnum::CAPABILITIES));

    packet_negotiate_algorithms_request_var request;
    request.Min.Header.MessageVersion = MessageVersion;
    request.Min.Length = sizeof(request.Min);
    request.Min.MeasurementSpecification = 1 << 0;
    // 		request.Min.BaseAsymAlgo = BaseAsymAlgoFlags::TPM_ALG_RSASSA_2048 |
    // BaseAsymAlgoFlags::TPM_ALG_RSAPSS_2048;
    request.Min.BaseAsymAlgo = BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P256 |
                               BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P384;
    request.Min.BaseHashAlgo = BaseHashAlgoFlags::TPM_ALG_SHA_256 |
                               BaseHashAlgoFlags::TPM_ALG_SHA_384 |
                               BaseHashAlgoFlags::TPM_ALG_SHA_512;
    // 		request.Flags = RequesterCapabilitiesFlags::CERT_CAP |
    // RequesterCapabilitiesFlags::CHAL_CAP;

    request.PacketReqAlgVector.push_back(
        PacketReqAlgStruct::buildSupported2(AlgTypeEnum::DHE, 0x1b, 0x00));
    request.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildSupported2(
        AlgTypeEnum::AEADCipherSuite, 0x06, 0x00));
    request.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildSupported2(
        AlgTypeEnum::ReqBaseAsymAlg, 0x0F, 0x00));
    request.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildSupported2(
        AlgTypeEnum::KeySchedule, 0x01, 0x00));
    request.finalize();

    auto rs = send_request_setup_response(
        request, packet_algorithms_response_var(), BufEnum::A, Timings.getT1());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handle_recv<packet_algorithms_response_var>()
{
    packet_algorithms_response_var& resp = Algorithms;
    auto rs = interpret_response(resp);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    MarkInfo(ConnectionInfoEnum::ALGORITHMS);

    AppendRecvToBuf(BufEnum::A);

    PacketDecodeInfo.MeasurementHashSize =
        get_hash_size(resp.Min.MeasurementHashAlgo);
    PacketDecodeInfo.BaseHashSize = get_hash_size(resp.Min.BaseHashAlgo);
    PacketDecodeInfo.SignatureSize = get_signature_size(resp.Min.BaseAsymAlgo);

    rs = try_get_digest();
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

RetStat ConnectionClass::try_get_digest()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    assert(HasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));
    assert(HasInfo(ConnectionInfoEnum::ALGORITHMS));

    packet_get_digests_request request;
    request.Header.MessageVersion = MessageVersion;

    auto rs = send_request_setup_response(
        request, packet_digests_response_var(), BufEnum::B, Timings.getT1());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handle_recv<packet_digests_response_var>()
{
    packet_digests_response_var resp;
    auto rs = interpret_response(resp, PacketDecodeInfo);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    bool skip_cert = false;
    for (SlotIdx i = 0; i < SLOT_NUM; ++i)
    {
        if (resp.Min.Header.Param2 & (1 << i))
        {
            if (i == CertificateSlotIdx &&
                SlotHasInfo(i, SlotInfoEnum::DIGEST) &&
                SlotHasInfo(i, SlotInfoEnum::CERTIFICATES) &&
                resp.Digests[i] == Slots[i].Digest)
            {
                skip_cert = true;
            }
            else
            {
                std::swap(resp.Digests[i], Slots[i].Digest);
                Slots[i].MarkInfo(SlotInfoEnum::DIGEST);
            }
        }
        else
        {
            // clear slot data in case it is no longer valid
            Slots[i].clear();
            // TODO this may not necessarily be the correct behaviour?
        }
    }
    MarkInfo(ConnectionInfoEnum::DIGESTS);

    AppendRecvToBuf(BufEnum::B);
    if (skip_cert)
    {
        rs = try_challenge();
        SPDMCPP_LOG_TRACE_RS(Log, rs);
    }
    else
    {
        rs = try_get_certificate(CertificateSlotIdx);
        SPDMCPP_LOG_TRACE_RS(Log, rs);
    }
    return rs;
}

RetStat ConnectionClass::try_get_certificate_chunk(SlotIdx slotidx)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    assert(HasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));
    assert(HasInfo(ConnectionInfoEnum::ALGORITHMS));

    assert(MessageVersion != MessageVersionEnum::UNKNOWN);
    if (slotidx >= SLOT_NUM)
    {
        return RetStat::ERROR_UNKNOWN;
    }
    std::vector<uint8_t>& cert = Slots[slotidx].Certificates;

    packet_get_certificate_request request;
    request.Header.MessageVersion = MessageVersion;
    request.Header.Param1 = slotidx;
    request.Offset = cert.size();
    request.Length = 0xFFFF;
    // 		request.Length = 0x400;

    auto rs =
        send_request_setup_response(request, packet_certificate_response_var(),
                                    BufEnum::B, Timings.getT1());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handle_recv<packet_certificate_response_var>()
{
    packet_certificate_response_var resp;
    auto rs = interpret_response(resp);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    AppendRecvToBuf(BufEnum::B);

    SlotIdx idx = CertificateSlotIdx; // TODO WARNING
    SlotClass& slot = Slots[idx];
    std::vector<uint8_t>& cert = slot.Certificates;
    if (cert.empty())
    {
        cert.reserve(resp.Min.PortionLength + resp.Min.RemainderLength);
    }
    //	if (request.Offset != cert.size()) {//TODO
    {
        size_t off = cert.size();
        cert.resize(off + resp.Min.PortionLength);
        std::copy(resp.CertificateVector.begin(), resp.CertificateVector.end(),
                  cert.begin() + off); // TODO @Timon optimize?!
    }
    if (resp.Min.RemainderLength)
    {
        rs = try_get_certificate_chunk(idx);
        SPDMCPP_LOG_TRACE_RS(Log, rs);
        return rs;
    }
    else
    {
        {
            std::vector<uint8_t> hash;
            HashClass::compute(hash, getSignatureHash(), cert);
            Log.iprint("computed certificate digest hash = ");
            Log.println(hash.data(), hash.size());

            if (!std::equal(hash.begin(), hash.end(), slot.Digest.begin()))
            {
                Log.iprintln("certificate chain DIGEST verify FAILED!");
                return RetStat::ERROR_CERTIFICATE_CHAIN_DIGEST_INVALID;
            }
        }
        packet_certificate_chain cert_chain;
        size_t off = 0;
        rs = packet_decode_internal(cert_chain, cert, off);
        SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

        assert(cert_chain.Length == cert.size());
        std::vector<uint8_t> root_cert_hash;
        {
            root_cert_hash.resize(get_hash_size(Algorithms.Min.BaseHashAlgo));
            rs = packet_decode_basic(root_cert_hash, cert, off);
            SPDMCPP_LOG_TRACE_RS(Log, rs);
            Log.iprint("provided root certificate hash = ");
            Log.println(root_cert_hash.data(), root_cert_hash.size());
        }

        slot.CertificateOffset = off;

        do
        {
#define SPDMCPP_MBEDTLS_VAR_CREATE(type, var)                                  \
    type* var = reinterpret_cast<type*>(malloc(sizeof(type)));                 \
    type##_init(var)
            SPDMCPP_MBEDTLS_VAR_CREATE(mbedtls_x509_crt, c);

            int ret =
                mbedtls_x509_crt_parse_der(c, &cert[off], cert.size() - off);
            //	int ret = mbedtls_x509_crt_parse_der_nocopy(c, &cert[off],
            // cert.size() - off);
            if (ret)
            {
                Log.iprint("mbedtls_x509_crt_parse_der ret = ");
                Log.print(ret);
                Log.print(" = '");
                // Log.print(mbedtls_high_level_strerr(ret));
                mbedtls_strerror(ret, err_msg, sizeof(err_msg));
                Log.print((const char*)err_msg);
                Log.println('\'');
            }
            assert(ret == 0);

            slot.MCertificates.push_back(c);

            size_t asn1_len = 0;
            {
                uint8_t* s = cert.data() + off;
                uint8_t* p = s;
                ret = mbedtls_asn1_get_tag(
                    &p, cert.data() + cert.size(), &asn1_len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
                assert(ret == 0);
                asn1_len += (p - s);
            }

            if (slot.MCertificates.size() == 1)
            {
                std::vector<uint8_t> hash;
                hash.resize(get_hash_size(Algorithms.Min.BaseHashAlgo));
                int ret = mbedtls_md(
                    mbedtls_md_info_from_type(to_mbedtls(getSignatureHash())),
                    cert.data() + off, asn1_len, hash.data());
                assert(ret == 0);
                Log.iprint("computed root certificate hash = ");
                Log.println(hash.data(), hash.size());

                if (!std::equal(hash.begin(), hash.end(),
                                root_cert_hash.begin()))
                {
                    Log.iprintln("root certificate DIGEST verify FAILED!");
                    return RetStat::ERROR_ROOT_CERTIFICATE_HASH_INVALID;
                }
            }
            off += asn1_len;
        } while (off < cert.size());

        {
            std::string info;
            for (mbedtls_x509_crt* c : slot.MCertificates)
            {
                info.resize(4096);
                int ret =
                    mbedtls_x509_crt_info(info.data(), info.size(), "", c);
                assert(ret >= 0);
                info.resize(ret);
                Log.print(info);
            }
        }

#if 1
        for (size_t i = 1; i < slot.MCertificates.size(); ++i)
        { // TODO verify/fix
            slot.MCertificates[i]->next = slot.MCertificates[i - 1];
            uint32_t rflags = 0;
            // TODO shouldn't it be verified against something in the system?!
            // 				int ret =
            // mbedtls_x509_crt_verify(slot.GetLeafCert(), slot.GetRootCert(),
            // nullptr, "intel test ECP256 responder cert", &rflags, nullptr,
            // nullptr); 				int ret =
            // mbedtls_x509_crt_verify(slot.GetLeafCert(), slot.GetRootCert(),
            // nullptr, nullptr, &rflags, nullptr, nullptr);
            int ret = mbedtls_x509_crt_verify(
                slot.MCertificates[i - 1], slot.MCertificates[i], nullptr,
                nullptr, &rflags, nullptr, nullptr);
            Log.iprint("mbedtls_x509_crt_verify ret = ");
            Log.println(ret);
            if (ret)
            {
                std::string info;
                info.resize(4096);
                ret = mbedtls_x509_crt_verify_info(info.data(), info.size(), "",
                                                   rflags);
                assert(ret >= 0);
                info.resize(ret);
                Log.print(info);
                return RetStat::ERROR_CERTIFICATE_CHAIN_VERIFIY_FAILED;
            }
        }
#else
        if (slot.MCertificates.size() >= 2)
        {
            /*	for (size_t i = 1; i < slot.MCertificates.size() - 1; ++i) {
                    slot.MCertificates[i - 1]->next = slot.MCertificates[i];
                }*/
            /*	for (size_t i = 1; i < slot.MCertificates.size() - 1; ++i) {
                    slot.MCertificates[i]->next = slot.MCertificates[i - 1];
                }*/
        }
        {
            uint32_t rflags = 0;
            // 				int ret =
            // mbedtls_x509_crt_verify(slot.GetLeafCert(), slot.GetRootCert(),
            // nullptr, "intel test ECP256 responder cert", &rflags, nullptr,
            // nullptr);
            int ret = mbedtls_x509_crt_verify(
                slot.GetLeafCert(), slot.GetRootCert(), nullptr, nullptr,
                &rflags, nullptr, nullptr);
            Log.iprint("mbedtls_x509_crt_verify ret = ");
            Log.println(ret);
            if (ret)
            {
                std::string info;
                info.resize(4096);
                ret = mbedtls_x509_crt_verify_info(info.data(), info.size(), "",
                                                   rflags);
                assert(ret >= 0);
                info.resize(ret);
                Log.print(info);
                assert(false);
            }
        }
#endif
        slot.MarkInfo(SlotInfoEnum::CERTIFICATES);

        rs = try_challenge();
        SPDMCPP_LOG_TRACE_RS(Log, rs);
    }
    return rs;
}

RetStat ConnectionClass::try_get_certificate(SlotIdx idx)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    assert(HasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));
    assert(HasInfo(ConnectionInfoEnum::ALGORITHMS));

    if (idx >= SLOT_NUM)
    {
        return RetStat::ERROR_UNKNOWN;
    }
    std::vector<uint8_t>& cert = Slots[idx].Certificates;
    // assert(cert.empty());
    cert.clear();

    auto rs = try_get_certificate_chunk(idx);
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

RetStat ConnectionClass::try_challenge()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    assert(MessageVersion != MessageVersionEnum::UNKNOWN);

    packet_challenge_request request;
    request.Header.MessageVersion = MessageVersion;
    request.Header.Param1 = CertificateSlotIdx; // TODO !!! DECIDE
    request.Header.Param2 = PacketDecodeInfo.ChallengeParam2 = 0xFF;
    // 		request.Header.Param2 = PacketDecodeInfo.ChallengeParam2 = 1;
    fill_random(request.Nonce);

    auto rs = send_request_setup_response(request,
                                          packet_challenge_auth_response_var(),
                                          BufEnum::C, Timings.getT2());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

template <>
RetStat ConnectionClass::handle_recv<packet_challenge_auth_response_var>()
{
    packet_challenge_auth_response_var resp;
    auto rs = interpret_response(resp, PacketDecodeInfo);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    AppendToBuf(BufEnum::C, &ResponseBuffer[ResponseBufferSPDMOffset],
                ResponseBuffer.size() - ResponseBufferSPDMOffset -
                    PacketDecodeInfo.SignatureSize);

    {
        std::vector<uint8_t> hash;
        {
            HashClass ha;
            ha.setup(getSignatureHash());
            // for (BufEnum::NUM)
            for (std::vector<uint8_t>& buf : Bufs)
            {
                if (!buf.empty())
                {
                    ha.update(buf);
                }
            }
            ha.hash_finish(hash);
        }
        Log.iprint("computed m2 hash = ");
        Log.println(hash.data(), hash.size());

        // 			HashM1M2.hash_finish(hash.data(), hash.size());
        // 			Log.iprint("computed m2 hash = ");
        // 			Log.println(hash.data(), hash.size());

        Log.iprint("resp.SignatureVector = ");
        Log.println(resp.SignatureVector.data(), resp.SignatureVector.size());
        // 			resp.SignatureVector[10] = 'X';	//TODO TEST

        {
            // TODO SlotIdx
            int ret = verify_signature(Slots[CertificateSlotIdx].GetLeafCert(),
                                       resp.SignatureVector, hash);
            SPDMCPP_LOG_TRACE_RS(Log, ret);
            if (!ret)
            {
                Log.iprintln(
                    "challenge_auth_response SIGNATURE verify PASSED!");
            }
            else
            {
                Log.iprint("mbedtls_ecdsa_verify ret = ");
                Log.print(ret);
                Log.print(" = '");
                mbedtls_strerror(ret, err_msg, sizeof(err_msg));
                Log.print((const char*)err_msg);
                Log.print("'	'");
                // if (const char* msg = mbedtls_low_level_strerr(ret)) {
                //	Log.print(msg);
                // }
                Log.println('\'');
                return RetStat::ERROR_AUTHENTICATION_FAILED;
            }
        }
        rs = try_get_measurements();
        SPDMCPP_LOG_TRACE_RS(Log, rs);
    }
    return rs;
}

RetStat ConnectionClass::try_get_measurements()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    assert(MessageVersion != MessageVersionEnum::UNKNOWN);

    HashL1L2.setup(getSignatureHash());

    packet_get_measurements_request_var request;
    request.Min.Header.MessageVersion = MessageVersion;
    {
        request.Min.Header.Param1 = PacketDecodeInfo.GetMeasurementsParam1 =
            0x1;
        request.set_nonce();
        memcpy(request.Nonce, MeasurementNonce, sizeof(request.Nonce));
    }
    request.Min.Header.Param2 = PacketDecodeInfo.GetMeasurementsParam2 = 0xFF;

    auto rs =
        send_request_setup_response(request, packet_measurements_response_var(),
                                    BufEnum::L, Timings.getT2());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

template <>
RetStat ConnectionClass::handle_recv<packet_measurements_response_var>()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    packet_measurements_response_var resp;
    auto rs = interpret_response(resp, PacketDecodeInfo);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    HashL1L2.update(&ResponseBuffer[ResponseBufferSPDMOffset],
                    ResponseBuffer.size() - ResponseBufferSPDMOffset -
                        PacketDecodeInfo.SignatureSize);

    AppendToBuf(BufEnum::L, &ResponseBuffer[ResponseBufferSPDMOffset],
                ResponseBuffer.size() - ResponseBufferSPDMOffset -
                    PacketDecodeInfo.SignatureSize);

    std::vector<uint8_t> hash;
#if 1
    HashL1L2.hash_finish(hash);
#else
    HashBuf(hash, getSignatureHash(), BufEnum::L);
#endif
    Log.iprint("computed l2 hash = ");
    Log.println(hash.data(), hash.size());

    int ret = verify_signature(Slots[CertificateSlotIdx].GetLeafCert(),
                               resp.SignatureVector, hash);
    SPDMCPP_LOG_TRACE_RS(Log, ret);
    if (!ret)
    {
        Log.iprintln("measurements SIGNATURE verify PASSED!");

        SlotIdx idx = CertificateSlotIdx; // TODO WARNING
        SlotClass& slot = Slots[idx];
        slot.DMTFMeasurements.clear();
        // parse DMTF Measurements
        for (const auto& block : resp.MeasurementBlockVector)
        {
            if (block.Min.MeasurementSpecification == 1)
            {
                if (slot.DMTFMeasurements.find(block.Min.Index) !=
                    slot.DMTFMeasurements.end())
                {
                    Log.iprintln(
                        "DUPLICATE MeasurementBlock Index!"); // TODO Warning!!!
                }
                else
                {
                    size_t off = 0;
                    auto rs = packet_decode_internal(
                        slot.DMTFMeasurements[block.Min.Index],
                        block.MeasurementVector, off);
                    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);
                    if (off != block.MeasurementVector.size())
                    {
                        Log.iprintln(
                            "MeasurementBlock not fully parsed!"); // TODO
                                                                   // Warning!!!
                    }
                }
            }
        }
        slot.MarkInfo(SlotInfoEnum::MEASUREMENTS);
    }
    else
    {
        Log.iprint("mbedtls_ecdsa_verify ret = ");
        Log.print(ret);
        Log.print(" = '");
        mbedtls_strerror(ret, err_msg, sizeof(err_msg));
        Log.print((const char*)err_msg);
        Log.print("'	'");
        // if (const char* msg = mbedtls_low_level_strerr(ret)) {
        //	Log.print(msg);
        // }
        Log.println('\'');
        return RetStat::ERROR_MEASUREMENT_SIGNATURE_VERIFIY_FAILED;
    }
    //	Transport->setup_timeout(1000);
    return rs;
}

RetStat ConnectionClass::handle_recv()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);

    clear_timeout();

    Log.iprint("ResponseBuffer.size() = ");
    Log.println(ResponseBuffer.size());
    Log.iprint("ResponseBuffer = ");
    Log.println(ResponseBuffer.data(), ResponseBuffer.size());

    RequestResponseEnum code;
    {
        TransportClass::LayerState lay; // TODO double decode
        if (Transport)
        {
            auto rs = Transport->decode(ResponseBuffer, lay);
            SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);
        }
        ResponseBufferSPDMOffset = lay.get_end_offset();
        code = packet_message_header_get_requestresponsecode(
            ResponseBuffer.data() + ResponseBufferSPDMOffset);
    }

    if (code == RequestResponseEnum::RESPONSE_ERROR)
    {
        Log.iprint("RESPONSE_ERROR while waiting for response: ");
        Log.println(WaitingForResponse);
        WaitingForResponse = RequestResponseEnum::INVALID;

        packet_error_response_var err;
        auto rs = interpret_response(err);
        SPDMCPP_LOG_TRACE_RS(Log, rs);
        return RetStat::ERROR_RESPONSE;
    }
    if (code != WaitingForResponse)
    {
        Log.iprint("ERROR_WRONG_REQUEST_RESPONSE_CODE: ");
        Log.println(code);
        Log.iprint(" while waiting for response: ");
        Log.println(WaitingForResponse);
        WaitingForResponse = RequestResponseEnum::INVALID;
        return RetStat::ERROR_WRONG_REQUEST_RESPONSE_CODE;
    }
    WaitingForResponse = RequestResponseEnum::INVALID;

    RetStat rs = RetStat::ERROR_UNKNOWN;
    switch (code)
    {
#define DTYPE(type)                                                            \
    case type::RequestResponseCode:                                            \
        rs = handle_recv<type>();                                              \
        break;
        DTYPE(packet_version_response_var)
        DTYPE(packet_capabilities_response)
        DTYPE(packet_algorithms_response_var)
        DTYPE(packet_digests_response_var)
        DTYPE(packet_certificate_response_var)
        DTYPE(packet_challenge_auth_response_var)
        DTYPE(packet_measurements_response_var)
        default:
            Log.iprint("!!! Unknown code: ");
            Log.println(code);
            return RetStat::ERROR_UNKNOWN_REQUEST_RESPONSE_CODE;
    }
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);
    return rs;
}

RetStat ConnectionClass::handle_timeout()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    if (SendRetry)
    {
        --SendRetry;
        auto rs = Context->IO->write(SendBuffer);
        SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

        rs = Transport->setup_timeout(SendTimeout);
        SPDMCPP_LOG_TRACE_RS(Log, rs);
        return rs;
    }
    WaitingForResponse = RequestResponseEnum::INVALID;
    return RetStat::ERROR_TIMEOUT;
}

void ConnectionClass::clear_timeout()
{
    Transport->clear_timeout();
    SendTimeout = 0;
    SendRetry = 0;
}

} // namespace spdmcpp

#undef SPDMCPP_CONNECTION_RS_ERROR_RETURN
