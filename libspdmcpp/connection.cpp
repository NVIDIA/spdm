
#include <mbedtls/ecdh.h>
#include <mbedtls/error.h>

#include <spdmcpp/connection.hpp>
#include <spdmcpp/connection_inl.hpp>
#include <spdmcpp/context.hpp>
#include <spdmcpp/helpers.hpp>
#include <spdmcpp/mbedtls_support.hpp>

#include <algorithm>
#include <fstream>

char err_msg[64]; // TODO remove! not thread safe

namespace spdmcpp
{
RetStat ConnectionClass::init_connection()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    HashM1M2.setup(MBEDTLS_MD_SHA384);

    auto rs = try_get_version();
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    /*	if (RETURN_ERROR(status)) {
            return status;
        }*/
    /*	rs = choose_version();
        SPDMCPP_LOG_TRACE_RS(Log, rs);
        Log.iprint("chosen MessageVersion: ");
        Log.println(MessageVersion);

        rs = try_get_capabilities();
        SPDMCPP_LOG_TRACE_RS(Log, rs);

        rs = try_negotiate_algorithms();
        SPDMCPP_LOG_TRACE_RS(Log, rs);

        rs = try_get_digest();
        SPDMCPP_LOG_TRACE_RS(Log, rs);

        rs = try_get_certificate(0);
        SPDMCPP_LOG_TRACE_RS(Log, rs);

        rs = try_get_certificate(3);
        SPDMCPP_LOG_TRACE_RS(Log, rs);
        */
    return RetStat::OK;
}

RetStat ConnectionClass::try_get_version()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    assert(MessageVersion == MessageVersionEnum::UNKNOWN);

    packet_get_version_request spdm_request;
    auto rs = send_request_setup_response(
        spdm_request, packet_get_version_response_var(), BufEnum::A);
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handle_recv<packet_get_version_response_var>()
{
    packet_get_version_response_var resp;
    auto rs = interpret_response(resp);
    SPDMCPP_LOG_TRACE_RS(Log, rs);

    if (resp.Min.Header.MessageVersion != MessageVersionEnum::SPDM_1_0)
    {
        return RetStat::ERROR_UNKNOWN; // TODO
    }
    if (is_error(rs))
    {
        return rs;
    }
    // TODO a lot more checks?
    std::swap(SupportedVersions, resp.VersionNumberEntries);
    MarkInfo(ConnectionInfoEnum::SUPPORTED_VERSIONS);

    AppendRecvToBuf(BufEnum::A);

    choose_version();

    Log.iprint("chosen MessageVersion: ");
    Log.println(MessageVersion);

    try_get_capabilities();

    return RetStat::OK;
}

RetStat ConnectionClass::choose_version()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    assert(HasInfo(ConnectionInfoEnum::SUPPORTED_VERSIONS));
    assert(MessageVersion == MessageVersionEnum::UNKNOWN);

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
    return RetStat::ERROR_UNKNOWN;
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
        request, packet_get_capabilities_response(), BufEnum::A);
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handle_recv<packet_get_capabilities_response>()
{
    packet_get_capabilities_response resp;
    auto rs = interpret_response(resp);
    SPDMCPP_LOG_TRACE_RS(Log, rs);

    MarkInfo(ConnectionInfoEnum::CAPABILITIES);
    AppendRecvToBuf(BufEnum::A);

    try_negotiate_algorithms();
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
    // 			request.Min.BaseAsymAlgo =
    // BaseAsymAlgoFlags::TPM_ALG_RSASSA_2048 |
    // BaseAsymAlgoFlags::TPM_ALG_RSAPSS_2048;
    request.Min.BaseAsymAlgo = BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P256 |
                               BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P384;
    request.Min.BaseHashAlgo = BaseHashAlgoFlags::TPM_ALG_SHA_256 |
                               BaseHashAlgoFlags::TPM_ALG_SHA_384 |
                               BaseHashAlgoFlags::TPM_ALG_SHA_512;
    // 			request.Flags = RequesterCapabilitiesFlags::CERT_CAP |
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
        request, packet_algorithms_response_var(), BufEnum::A);
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handle_recv<packet_algorithms_response_var>()
{
    packet_algorithms_response_var& resp = Algorithms;
    auto rs = interpret_response(resp);
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    assert(rs == RetStat::OK);

    MarkInfo(ConnectionInfoEnum::ALGORITHMS);

    AppendRecvToBuf(BufEnum::A);

    //	PacketDecodeInfo.MeasurementHashSize =
    // mbedtls_md_info_from_type(to_mbedtls(resp.Min.MeasurementHashAlgo)).size;
    //	PacketDecodeInfo.BaseHashSize =
    // mbedtls_md_info_from_type(to_mbedtls(resp.Min.BaseHashAlgo)).size;
    PacketDecodeInfo.MeasurementHashSize =
        get_hash_size(resp.Min.MeasurementHashAlgo);
    PacketDecodeInfo.BaseHashSize = get_hash_size(resp.Min.BaseHashAlgo);
    PacketDecodeInfo.SignatureSize = get_signature_size(resp.Min.BaseAsymAlgo);

    try_get_digest();

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
        request, packet_digests_response_var(), BufEnum::B);
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handle_recv<packet_digests_response_var>()
{
    packet_digests_response_var resp;
    auto rs = interpret_response(resp, PacketDecodeInfo);
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    assert(rs == RetStat::OK);

    for (SlotIdx i = 0; i < SLOT_NUM; ++i)
    {
        if (resp.Min.Header.Param2 & (1 << i))
        {
            std::swap(resp.DigestVector[i], Slots[i].Digest);
        }
    }
    MarkInfo(ConnectionInfoEnum::DIGESTS);

    AppendRecvToBuf(BufEnum::B);

    try_get_certificate(0);
    return rs;
}

RetStat ConnectionClass::try_get_certificate_chunk(SlotIdx idx)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    assert(HasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));
    assert(HasInfo(ConnectionInfoEnum::ALGORITHMS));

    assert(MessageVersion != MessageVersionEnum::UNKNOWN);
    if (idx >= SLOT_NUM)
    {
        return RetStat::ERROR_UNKNOWN;
    }
    std::vector<uint8_t>& cert = Slots[idx].Certificates;

    packet_get_certificate_request request;
    request.Header.MessageVersion = MessageVersion;
    request.Header.Param1 = idx;
    request.Offset = cert.size();
    request.Length = 0xFFFF;
    // 		request.Length = 0x400;

    auto rs = send_request_setup_response(
        request, packet_certificate_response_var(), BufEnum::B);
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handle_recv<packet_certificate_response_var>()
{
    packet_certificate_response_var resp;
    auto rs = interpret_response(resp);
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    assert(rs == RetStat::OK);

    AppendRecvToBuf(BufEnum::B);

    SlotIdx idx = 0; // TODO WARNING
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
        return try_get_certificate_chunk(idx);
    }
    else
    {
        // 			cert[12] = 'X';	//TODO TEST
        Log.iprint("got cert: size = ");
        Log.print(cert.size());
        Log.print(": ");
        Log.println(cert.data(), cert.size());

        /*	{
                std::fstream s("cert.pem", s.binary | s.trunc | s.in | s.out);
                s.write(reinterpret_cast<char*>(cert.data()), cert.size());
                s.sync();
            }*/
        {
            std::vector<uint8_t> hash;
            hash.resize(get_hash_size(Algorithms.Min.BaseHashAlgo));
            int ret = mbedtls_md(mbedtls_md_info_from_type(
                                     to_mbedtls(Algorithms.Min.BaseHashAlgo)),
                                 cert.data(), cert.size(), hash.data());
            assert(ret == 0);
            Log.iprint("computed certificate digest hash = ");
            Log.println(hash.data(), hash.size());
            if (!std::equal(hash.begin(), hash.end(), slot.Digest.begin()))
            {
                Log.iprintln("certificate chain DIGEST verify FAILED!");
                assert(false);
            }
            else
            {
                Log.iprintln("certificate chain DIGEST verify PASSED!");
            }
        }
        packet_certificate_chain
            cert_chain; // TODO create a standard _var packet and just parse
                        // from cert_chain? seems like it fits surprisingly
                        // nicely!
        size_t off = 0;
        rs = packet_decode_internal(cert_chain, cert, off);
        SPDMCPP_LOG_TRACE_RS(Log, rs);
        assert(cert_chain.Length == cert.size());
        std::vector<uint8_t> root_cert_hash;
        {
            root_cert_hash.resize(get_hash_size(Algorithms.Min.BaseHashAlgo));
            rs = packet_decode_basic(root_cert_hash, cert, off);
            SPDMCPP_LOG_TRACE_RS(Log, rs);
            Log.iprint("provided root certificate hash = ");
            Log.println(root_cert_hash.data(), root_cert_hash.size());
        }

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
            // 				cert[off + 12] = 'X';	//TODO TEST
            if (slot.MCertificates.size() == 1)
            {
                std::vector<uint8_t> hash;
                hash.resize(get_hash_size(Algorithms.Min.BaseHashAlgo));
                int ret = mbedtls_md(mbedtls_md_info_from_type(to_mbedtls(
                                         Algorithms.Min.BaseHashAlgo)),
                                     cert.data() + off, asn1_len, hash.data());
                assert(ret == 0);
                Log.iprint("computed root certificate hash = ");
                Log.println(hash.data(), hash.size());
                if (!std::equal(hash.begin(), hash.end(),
                                root_cert_hash.begin()))
                {
                    Log.iprintln("root certificate DIGEST verify FAILED!");
                    assert(false);
                }
                else
                {
                    Log.iprintln("root certificate DIGEST verify PASSED!");
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
                assert(false);
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
        try_challenge();
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
    assert(cert.empty());

    return try_get_certificate_chunk(idx);
}

RetStat ConnectionClass::try_challenge()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    assert(MessageVersion != MessageVersionEnum::UNKNOWN);

    packet_challenge_request request;
    request.Header.MessageVersion = MessageVersion;
    request.Header.Param2 = PacketDecodeInfo.ChallengeParam2 = 0xFF;
    // 		request.Header.Param2 = PacketDecodeInfo.ChallengeParam2 = 1;
    fill_random(request.Nonce);

    auto rs = send_request_setup_response(
        request, packet_challenge_auth_response_var(), BufEnum::C);
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    assert(rs == RetStat::OK);
    return rs;
}

template <>
RetStat ConnectionClass::handle_recv<packet_challenge_auth_response_var>()
{
    packet_challenge_auth_response_var resp;
    auto rs = interpret_response(resp, PacketDecodeInfo);
    SPDMCPP_LOG_TRACE_RS(Log, rs);

    AppendToBuf(BufEnum::C, &ResponseBuffer[ResponseBufferSPDMOffset],
                ResponseBuffer.size() - ResponseBufferSPDMOffset -
                    PacketDecodeInfo.SignatureSize);

    assert(rs == RetStat::OK);
    {
        std::vector<uint8_t> hash;
        {
            HashClass ha;
            ha.setup(to_mbedtls(Algorithms.Min.BaseHashAlgo));
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
            int ret = verify_signature(Slots[0].GetLeafCert(),
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
            }
        }
        try_get_measurements();
    }
    return rs;
}

RetStat ConnectionClass::try_get_measurements()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    assert(MessageVersion != MessageVersionEnum::UNKNOWN);

    HashL1L2.setup(to_mbedtls(Algorithms.Min.BaseHashAlgo));

    packet_get_measurements_request_var request;
    request.Min.Header.MessageVersion = MessageVersion;
    {
        request.Min.Header.Param1 = PacketDecodeInfo.GetMeasurementsParam1 =
            0x1;
        request.set_nonce();
        fill_random(request.Nonce);
    }
    request.Min.Header.Param2 = PacketDecodeInfo.GetMeasurementsParam2 = 0xFF;

    auto rs = send_request_setup_response(request,
                                          packet_measurements_response_var());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    assert(rs == RetStat::OK);
    return rs;
}

template <>
RetStat ConnectionClass::handle_recv<packet_measurements_response_var>()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    packet_measurements_response_var resp;
    auto rs = interpret_response(resp, PacketDecodeInfo);
    SPDMCPP_LOG_TRACE_RS(Log, rs);

    HashL1L2.update(&ResponseBuffer[ResponseBufferSPDMOffset],
                    ResponseBuffer.size() - ResponseBufferSPDMOffset -
                        PacketDecodeInfo.SignatureSize);

    std::vector<uint8_t> hash;
    HashL1L2.hash_finish(hash);
    Log.iprint("computed l2 hash = ");
    Log.println(hash.data(), hash.size());

    int ret =
        verify_signature(Slots[0].GetLeafCert(), resp.SignatureVector, hash);
    SPDMCPP_LOG_TRACE_RS(Log, ret);
    if (!ret)
    {
        Log.iprintln("measurements SIGNATURE verify PASSED!");
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
    }

    Context->IO->setup_timeout(0);
    // 		Context->IO->setup_timeout(1000 * 1000);

    return rs;
}

EventRetStat ConnectionClass::handle_recv()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);

    Log.iprint("ResponseBuffer.size() = ");
    Log.println(ResponseBuffer.size());
    Log.iprint("ResponseBuffer = ");
    Log.println(ResponseBuffer.data(), ResponseBuffer.size());

    RequestResponseEnum code;
    {
        TransportClass::LayerState lay; // TODO double decode
        if (Context->Transport)
        {
            auto rs = Context->Transport->decode(ResponseBuffer, lay);
            SPDMCPP_LOG_TRACE_RS(Log, rs);
            if (rs != RetStat::OK)
            {
                return EventRetStat::ERROR_EXIT;
            }
        }
        ResponseBufferSPDMOffset = lay.get_end_offset();
        code = packet_message_header_get_requestresponsecode(
            ResponseBuffer.data() + ResponseBufferSPDMOffset);
    }
    assert(code == WaitingForResponse ||
           code == RequestResponseEnum::RESPONSE_ERROR);
    WaitingForResponse = RequestResponseEnum::INVALID;

    RetStat rs = RetStat::ERROR_UNKNOWN;
    switch (code)
    {
#define DTYPE(type)                                                            \
    case type::RequestResponseCode:                                            \
        rs = handle_recv<type>();                                              \
        break;
        DTYPE(packet_get_version_response_var)
        DTYPE(packet_get_capabilities_response)
        DTYPE(packet_algorithms_response_var)
        DTYPE(packet_digests_response_var)
        DTYPE(packet_certificate_response_var)
        DTYPE(packet_challenge_auth_response_var)
        DTYPE(packet_measurements_response_var)

        case packet_error_response_var::RequestResponseCode:
        {
            packet_error_response_var err;
            rs = interpret_response(err);
            SPDMCPP_LOG_TRACE_RS(Log, rs);
            assert(rs == RetStat::OK);
            return EventRetStat::ERROR_EXIT;
        }
        default:
            Log.iprint("!!! Unknown code: ");
            Log.println(code);
            break;
    }
    if (is_error(rs))
    {
        return EventRetStat::ERROR_EXIT;
    }
    return EventRetStat::OK;
}
EventRetStat ConnectionClass::handle_timeout()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    return EventRetStat::ERROR_EXIT;
}

} // namespace spdmcpp
