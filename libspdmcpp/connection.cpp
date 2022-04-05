
#include <mbedtls/ecdh.h>
#include <mbedtls/error.h>
#include <mbedtls/pem.h>

#include <spdmcpp/context.hpp>
#include <spdmcpp/connection.hpp>
#include <spdmcpp/connection_inl.hpp>
#include <spdmcpp/helpers.hpp>
#include <spdmcpp/mbedtls_support.hpp>

#include <algorithm>
#include <fstream>

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs)                                 \
    do                                                                         \
    {                                                                          \
        SPDMCPP_LOG_TRACE_RS(Log, (rs));                                       \
        if (isError(rs))                                                       \
            return rs;                                                         \
    } while (false)

namespace spdmcpp
{

ConnectionClass::ConnectionClass(ContextClass* context) :
    Context(context), Log(std::cout)
{}

RetStat ConnectionClass::initConnection()
{
    resetConnection();
    return refreshMeasurements(0); // TODO this should be param/config based!
}

RetStat ConnectionClass::refreshMeasurements(SlotIdx slotidx)
{
    CertificateSlotIdx = slotidx;
    fillRandom(MeasurementNonce);
    MeasurementIndices.reset();
    MeasurementIndices.set(255);
    return refreshMeasurementsInternal();
}
RetStat ConnectionClass::refreshMeasurements(SlotIdx slotidx,
                                             const nonce_array_32& nonce)
{
    CertificateSlotIdx = slotidx;
    MeasurementNonce = nonce;
    MeasurementIndices.reset();
    MeasurementIndices.set(255);
    return refreshMeasurementsInternal();
}
RetStat ConnectionClass::refreshMeasurements(
    SlotIdx slotidx, const std::bitset<256>& measurementIndices)
{
    CertificateSlotIdx = slotidx;
    fillRandom(MeasurementNonce);
    MeasurementIndices = measurementIndices;
    return refreshMeasurementsInternal();
}
RetStat ConnectionClass::refreshMeasurements(
    SlotIdx slotidx, const nonce_array_32& nonce,
    const std::bitset<256>& measurementIndices)
{
    CertificateSlotIdx = slotidx;
    MeasurementNonce = nonce;
    MeasurementIndices = measurementIndices;
    return refreshMeasurementsInternal();
}
RetStat ConnectionClass::refreshMeasurementsInternal()
{
    if (MeasurementIndices[255])
    {
        SPDMCPP_ASSERT(MeasurementIndices.count() == 1);
    }
    else
    {
        SPDMCPP_ASSERT(!MeasurementIndices[0]);
        SPDMCPP_ASSERT(!MeasurementIndices[255]);
    }
    auto rs = tryGetVersion();
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

void ConnectionClass::resetConnection()
{
    clearTimeout();

    GotInfo = 0;
    CertificateSlotIdx = slotNum;
    MessageVersion = MessageVersionEnum::UNKNOWN;
    WaitingForResponse = RequestResponseEnum::INVALID;
    Algorithms = PacketAlgorithmsResponseVar();
    packetDecodeInfo = PacketDecodeInfo();
    SupportedVersions.clear();

    DMTFMeasurements.clear();
    MeasurementsHash.clear();
    MeasurementsSignature.clear();
    MeasurementNonce.fill(0);
    MeasurementIndices.reset();

    for (auto& s : Slots)
    {
        s.clear();
    }

    for (auto& b : Bufs)
    {
        b.clear();
    }
}

bool ConnectionClass::getCertificatesDER(std::vector<uint8_t>& buf,
                                         uint8_t slotidx) const
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    buf.clear();

    if (!slothasInfo(slotidx, SlotInfoEnum::CERTIFICATES))
    {
        return false;
    }

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
    if (auto cert = slot.getLeafCert())
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
    if (!hasInfo(ConnectionInfoEnum::CERTIFICATES))
        return false;

    str.clear();

    const SlotClass& slot = Slots[slotidx];
    if (!slot.Valid)
        return false;

    if (auto cert = slot.getLeafCert())
    {
        size_t off = str.size();
        size_t size = 1024;
        str.resize(off + size);
        int ret = mbedtls_pem_write_buffer(
            "", "", (const unsigned char*)cert->raw.p, cert->raw.len,
            (unsigned char*)str.data() + off, size, &size);
        SPDMCPP_ASSERT(ret == 0); // TODO make it robust
        str.resize(off + size);
        return true;
    }
    return false;
}
#endif

RetStat ConnectionClass::tryGetVersion()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    // SPDMCPP_ASSERT(MessageVersion == MessageVersionEnum::UNKNOWN);

    for (auto& b : Bufs)
    {
        b.clear();
    }

    PacketGetVersionRequest spdmRequest;
    auto rs = sendRequestSetupResponse(spdmRequest, PacketVersionResponseVar(),
                                       BufEnum::A, Timings.getT1());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handleRecv<PacketVersionResponseVar>()
{
    PacketVersionResponseVar resp;
    auto rs = interpretResponse(resp);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    if (resp.Min.Header.MessageVersion != MessageVersionEnum::SPDM_1_0)
    {
        return RetStat::ERROR_INVALID_HEADER_VERSION; // TODO generalize
    }

    // TODO a lot more checks?
    std::swap(SupportedVersions, resp.VersionNumberEntries);
    markInfo(ConnectionInfoEnum::SUPPORTED_VERSIONS);

    appendRecvToBuf(BufEnum::A);

    rs = chooseVersion();
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    Log.iprint("chosen MessageVersion: ");
    Log.println(MessageVersion);

    rs = tryGetCapabilities();
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

RetStat ConnectionClass::chooseVersion()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::SUPPORTED_VERSIONS));
    // SPDMCPP_ASSERT(MessageVersion == MessageVersionEnum::UNKNOWN);

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

    for (auto ours : Context->getSupportedVersions())
    {
        for (auto theirs : vers)
        {
            if (ours == theirs)
            {
                MessageVersion = theirs;
                markInfo(ConnectionInfoEnum::CHOOSEN_VERSION);
                return RetStat::OK;
            }
            if (theirs < ours)
            {
                break;
            }
        }
    }
    return RetStat::ERROR_UNSUPPORTED_SPDM_VERSION;
}

RetStat ConnectionClass::tryGetCapabilities()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));

    RetStat rs = RetStat::ERROR_UNKNOWN;
    if (MessageVersion == MessageVersionEnum::SPDM_1_0)
    {
        PacketGetCapabilities10Request request;
        request.Header.MessageVersion = MessageVersion;

        rs = sendRequestSetupResponse(request, PacketCapabilitiesResponse(),
                                      BufEnum::A, Timings.getT1());
        SPDMCPP_LOG_TRACE_RS(Log, rs);
    }
    else
    {
        PacketGetCapabilitiesRequest request;
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
            request.Flags |=
        RequesterCapabilitiesFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
            */

        rs = sendRequestSetupResponse(request, PacketCapabilitiesResponse(),
                                      BufEnum::A, Timings.getT1());
        SPDMCPP_LOG_TRACE_RS(Log, rs);
    }
    return rs;
}
template <>
RetStat ConnectionClass::handleRecv<PacketCapabilitiesResponse>()
{
    PacketCapabilitiesResponse resp;
    auto rs = interpretResponse(resp);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    markInfo(ConnectionInfoEnum::CAPABILITIES);
    appendRecvToBuf(BufEnum::A);

    // TODO verify more stuff here especially flags !!!
    Timings.setCTExponent(resp.CTExponent);

    rs = tryNegotiateAlgorithms();
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

RetStat ConnectionClass::tryNegotiateAlgorithms()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::CAPABILITIES));

    PacketNegotiateAlgorithmsRequestVar request;
    request.Min.Header.MessageVersion = MessageVersion;
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

    /*
    if (MessageVersion == MessageVersionEnum::SPDM_1_0) {

    }
    else
    {*/
    // request.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildSupported2(
    // AlgTypeEnum::ReqBaseAsymAlg, 0x0F, 0x00));
    /*request.PacketReqAlgVector.push_back(
        PacketReqAlgStruct::buildSupported2(AlgTypeEnum::DHE, 0x1b, 0x00));
    request.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildSupported2(
        AlgTypeEnum::AEADCipherSuite, 0x06, 0x00));
    request.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildSupported2(
        AlgTypeEnum::ReqBaseAsymAlg, 0x0F, 0x00));
    request.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildSupported2(
        AlgTypeEnum::KeySchedule, 0x01, 0x00));*/
    // }

    request.finalize();

    auto rs = sendRequestSetupResponse(request, PacketAlgorithmsResponseVar(),
                                       BufEnum::A, Timings.getT1());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handleRecv<PacketAlgorithmsResponseVar>()
{
    PacketAlgorithmsResponseVar& resp = Algorithms;
    auto rs = interpretResponse(resp);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    markInfo(ConnectionInfoEnum::ALGORITHMS);

    appendRecvToBuf(BufEnum::A);

    packetDecodeInfo.MeasurementHashSize =
        getHashSize(resp.Min.MeasurementHashAlgo);
    packetDecodeInfo.BaseHashSize = getHashSize(resp.Min.BaseHashAlgo);
    packetDecodeInfo.SignatureSize = getSignatureSize(resp.Min.BaseAsymAlgo);

    rs = tryGetDigest();
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

RetStat ConnectionClass::tryGetDigest()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::ALGORITHMS));

    PacketGetDigestsRequest request;
    request.Header.MessageVersion = MessageVersion;

    auto rs = sendRequestSetupResponse(request, PacketDigestsResponseVar(),
                                       BufEnum::B, Timings.getT1());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handleRecv<PacketDigestsResponseVar>()
{
    PacketDigestsResponseVar resp;
    auto rs = interpretResponse(resp, packetDecodeInfo);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    bool skipCert = false;
    for (SlotIdx i = 0; i < slotNum; ++i)
    {
        if (resp.Min.Header.Param2 & (1 << i))
        {
            if (i == CertificateSlotIdx &&
                slothasInfo(i, SlotInfoEnum::DIGEST) &&
                slothasInfo(i, SlotInfoEnum::CERTIFICATES) &&
                resp.Digests[i] == Slots[i].Digest)
            {
                skipCert = true;
            }
            else
            {
                std::swap(resp.Digests[i], Slots[i].Digest);
                Slots[i].markInfo(SlotInfoEnum::DIGEST);
            }
        }
        else
        {
            // clear slot data in case it is no longer valid
            Slots[i].clear();
            // TODO this may not necessarily be the correct behaviour?
        }
    }
    markInfo(ConnectionInfoEnum::DIGESTS);

    appendRecvToBuf(BufEnum::B);
    if (skipCert)
    {
        rs = tryChallenge();
        SPDMCPP_LOG_TRACE_RS(Log, rs);
    }
    else
    {
        rs = tryGetCertificate(CertificateSlotIdx);
        SPDMCPP_LOG_TRACE_RS(Log, rs);
    }
    return rs;
}

RetStat ConnectionClass::tryGetCertificateChunk(SlotIdx slotidx)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::ALGORITHMS));

    SPDMCPP_ASSERT(MessageVersion != MessageVersionEnum::UNKNOWN);
    if (slotidx >= slotNum)
    {
        return RetStat::ERROR_UNKNOWN;
    }
    std::vector<uint8_t>& cert = Slots[slotidx].Certificates;

    PacketGetCertificateRequest request;
    request.Header.MessageVersion = MessageVersion;
    request.Header.Param1 = slotidx;
    request.Offset = cert.size();
    request.Length = 0xFFFF;
    // 		request.Length = 0x400;

    auto rs = sendRequestSetupResponse(request, PacketCertificateResponseVar(),
                                       BufEnum::B, Timings.getT1());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}
template <>
RetStat ConnectionClass::handleRecv<PacketCertificateResponseVar>()
{
    PacketCertificateResponseVar resp;
    auto rs = interpretResponse(resp);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    appendRecvToBuf(BufEnum::B);

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
        rs = tryGetCertificateChunk(idx);
        SPDMCPP_LOG_TRACE_RS(Log, rs);
        return rs;
    }

    {
        {
            std::vector<uint8_t> hash;
            HashClass::compute(hash, getSignatureHash(), cert);
            Log.iprint("computed certificate digest hash = ");
            Log.println(hash);

            if (!std::equal(hash.begin(), hash.end(), slot.Digest.begin()))
            {
                Log.iprintln("certificate chain DIGEST verify FAILED!");
                return RetStat::ERROR_CERTIFICATE_CHAIN_DIGEST_INVALID;
            }
        }
        PacketCertificateChain certChain;
        size_t off = 0;
        rs = packetDecodeInternal(certChain, cert, off);
        SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

        SPDMCPP_ASSERT(certChain.Length == cert.size());
        std::vector<uint8_t> rootCertHash;
        {
            rootCertHash.resize(getHashSize(Algorithms.Min.BaseHashAlgo));
            rs = packetDecodeBasic(rootCertHash, cert, off);
            SPDMCPP_LOG_TRACE_RS(Log, rs);
            Log.iprint("provided root certificate hash = ");
            Log.println(rootCertHash);
        }

        slot.CertificateOffset = off;

        do
        {
            auto* c = new mbedtls_x509_crt;
            mbedtls_x509_crt_init(c);

            int ret =
                mbedtls_x509_crt_parse_der(c, &cert[off], cert.size() - off);
            //	int ret = mbedtls_x509_crt_parse_der_nocopy(c, &cert[off],
            // cert.size() - off);
            if (ret)
            {
                mbedtlsPrintErrorLine(Log, "mbedtls_x509_crt_parse_der()", ret);
            }
            SPDMCPP_ASSERT(ret == 0); // TODO proper error handling!!!

            slot.MCertificates.push_back(c);

            size_t asn1Len = 0;
            {
                uint8_t* s = cert.data() + off;
                uint8_t* p = s;
                ret = mbedtls_asn1_get_tag(
                    &p, cert.data() + cert.size(), &asn1Len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
                SPDMCPP_ASSERT(ret == 0);
                asn1Len += (p - s);
            }

            if (slot.MCertificates.size() == 1)
            {
                std::vector<uint8_t> hash;
                hash.resize(getHashSize(Algorithms.Min.BaseHashAlgo));
                int ret = mbedtls_md(
                    mbedtls_md_info_from_type(toMbedtls(getSignatureHash())),
                    cert.data() + off, asn1Len, hash.data());
                SPDMCPP_ASSERT(ret == 0);
                Log.iprint("computed root certificate hash = ");
                Log.println(hash);

                if (!std::equal(hash.begin(), hash.end(), rootCertHash.begin()))
                {
                    Log.iprintln("root certificate DIGEST verify FAILED!");
                    return RetStat::ERROR_ROOT_CERTIFICATE_HASH_INVALID;
                }
            }
            off += asn1Len;
        } while (off < cert.size());

        {
            std::string info;
            for (mbedtls_x509_crt* c : slot.MCertificates)
            {
                info.resize(4096);
                int ret =
                    mbedtls_x509_crt_info(info.data(), info.size(), "", c);
                SPDMCPP_ASSERT(ret >= 0);
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
            // mbedtls_x509_crt_verify(slot.getLeafCert(), slot.GetRootCert(),
            // nullptr, "intel test ECP256 responder cert", &rflags, nullptr,
            // nullptr); 				int ret =
            // mbedtls_x509_crt_verify(slot.getLeafCert(), slot.GetRootCert(),
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
                SPDMCPP_ASSERT(ret >= 0);
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
            // mbedtls_x509_crt_verify(slot.getLeafCert(), slot.GetRootCert(),
            // nullptr, "intel test ECP256 responder cert", &rflags, nullptr,
            // nullptr);
            int ret = mbedtls_x509_crt_verify(
                slot.getLeafCert(), slot.GetRootCert(), nullptr, nullptr,
                &rflags, nullptr, nullptr);
            Log.iprint("mbedtls_x509_crt_verify ret = ");
            Log.println(ret);
            if (ret)
            {
                std::string info;
                info.resize(4096);
                ret = mbedtls_x509_crt_verify_info(info.data(), info.size(), "",
                                                   rflags);
                SPDMCPP_ASSERT(ret >= 0);
                info.resize(ret);
                Log.print(info);
                SPDMCPP_ASSERT(false);
            }
        }
#endif
        slot.markInfo(SlotInfoEnum::CERTIFICATES);

        rs = tryChallenge();
        SPDMCPP_LOG_TRACE_RS(Log, rs);
    }
    return rs;
}

RetStat ConnectionClass::tryGetCertificate(SlotIdx idx)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));
    SPDMCPP_ASSERT(hasInfo(ConnectionInfoEnum::ALGORITHMS));

    if (idx >= slotNum)
    {
        return RetStat::ERROR_UNKNOWN;
    }
    std::vector<uint8_t>& cert = Slots[idx].Certificates;
    // SPDMCPP_ASSERT(cert.empty());
    cert.clear();

    auto rs = tryGetCertificateChunk(idx);
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

RetStat ConnectionClass::tryChallenge()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(MessageVersion != MessageVersionEnum::UNKNOWN);

    PacketChallengeRequest request;
    request.Header.MessageVersion = MessageVersion;
    request.Header.Param1 = CertificateSlotIdx; // TODO !!! DECIDE
    request.Header.Param2 = packetDecodeInfo.ChallengeParam2 = 0xFF;
    // 		request.Header.Param2 = packetDecodeInfo.ChallengeParam2 = 1;
    fillRandom(request.Nonce);

    auto rs = sendRequestSetupResponse(
        request, PacketChallengeAuthResponseVar(), BufEnum::C, Timings.getT2());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

template <>
RetStat ConnectionClass::handleRecv<PacketChallengeAuthResponseVar>()
{
    PacketChallengeAuthResponseVar resp;
    auto rs = interpretResponse(resp, packetDecodeInfo);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    appendToBuf(BufEnum::C, &ResponseBuffer[ResponseBufferSPDMOffset],
                ResponseBuffer.size() - ResponseBufferSPDMOffset -
                    packetDecodeInfo.SignatureSize);

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
            ha.hashFinish(hash);
        }
        Log.iprint("computed m2 hash = ");
        Log.println(hash);

        // HashM1M2.hashFinish(hash.data(), hash.size());
        // Log.iprint("computed m2 hash = ");
        // Log.println(hash.data(), hash.size());

        Log.iprint("resp.SignatureVector = ");
        Log.println(resp.SignatureVector);
        // resp.SignatureVector[10] = 'X';	//TODO TEST

        {
            // TODO SlotIdx
            int ret = verifySignature(Slots[CertificateSlotIdx].getLeafCert(),
                                      resp.SignatureVector, hash);
            SPDMCPP_LOG_TRACE_RS(Log, ret);
            if (!ret)
            {
                Log.iprintln(
                    "challenge_auth_response SIGNATURE verify PASSED!");
            }
            else
            {
                mbedtlsPrintErrorLine(Log, "mbedtls_ecdsa_verify()", ret);
                return RetStat::ERROR_AUTHENTICATION_FAILED;
            }
        }
        rs = tryGetMeasurements();
        SPDMCPP_LOG_TRACE_RS(Log, rs);
    }
    return rs;
}

RetStat ConnectionClass::tryGetMeasurements()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(MessageVersion != MessageVersionEnum::UNKNOWN);

    // SlotClass& slot = Slots[CertificateSlotIdx];

    // HashL1L2.setup(getSignatureHash());
    DMTFMeasurements.clear();

    if (MeasurementIndices[255])
    {
        MeasurementIndices.reset();
        return tryGetMeasurements(255);
    }
    if (MeasurementIndices.any())
    {
        uint8_t idx = getFirstMeasurementIndex();
        MeasurementIndices.reset(idx);
        return tryGetMeasurements(idx);
    }
    return RetStat::OK;
}

RetStat ConnectionClass::tryGetMeasurements(uint8_t idx)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    SPDMCPP_ASSERT(MessageVersion != MessageVersionEnum::UNKNOWN);

    PacketGetMeasurementsRequestVar request;
    request.Min.Header.MessageVersion = MessageVersion;

    if (MeasurementIndices.none())
    {
        request.Min.Header.Param1 = packetDecodeInfo.GetMeasurementsParam1 =
            0x1;
        request.setNonce();
        request.Nonce = MeasurementNonce;
        request.SlotIDParam = CertificateSlotIdx;
    }
    else
    {
        request.Min.Header.Param1 = packetDecodeInfo.GetMeasurementsParam1 =
            0x0;
    }

    request.Min.Header.Param2 = packetDecodeInfo.GetMeasurementsParam2 = idx;

    auto rs = sendRequestSetupResponse(request, PacketMeasurementsResponseVar(),
                                       BufEnum::L, Timings.getT2());
    SPDMCPP_LOG_TRACE_RS(Log, rs);
    return rs;
}

template <>
RetStat ConnectionClass::handleRecv<PacketMeasurementsResponseVar>()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    PacketMeasurementsResponseVar resp;
    auto rs = interpretResponse(resp, packetDecodeInfo);
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

    // parse and store DMTF Measurements
    for (const auto& block : resp.MeasurementBlockVector)
    {
        if (block.Min.MeasurementSpecification == 1)
        {
            if (DMTFMeasurements.find(block.Min.Index) !=
                DMTFMeasurements.end())
            {
                Log.iprintln("DUPLICATE MeasurementBlock Index!"); // TODO
                                                                   // Warning!!!
            }
            else
            {
                size_t off = 0;
                auto rs =
                    packetDecodeInternal(DMTFMeasurements[block.Min.Index],
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

    if (packetDecodeInfo.GetMeasurementsParam1 & 1)
    {
        /*HashL1L2.update(&ResponseBuffer[ResponseBufferSPDMOffset],
                        ResponseBuffer.size() - ResponseBufferSPDMOffset -
                            packetDecodeInfo.SignatureSize);*/

        appendToBuf(BufEnum::L, &ResponseBuffer[ResponseBufferSPDMOffset],
                    ResponseBuffer.size() - ResponseBufferSPDMOffset -
                        packetDecodeInfo.SignatureSize);

        { // store measurement signature
            MeasurementsSignature.resize(packetDecodeInfo.SignatureSize);
            size_t off = ResponseBuffer.size() - MeasurementsSignature.size();
            memcpy(MeasurementsSignature.data(), &ResponseBuffer[off],
                   MeasurementsSignature.size());
        }
        std::vector<uint8_t>& hash = MeasurementsHash;
        hash.clear();
#if 0
        HashL1L2.hashFinish(hash);
#else
        hashBuf(hash, getSignatureHash(), BufEnum::L);
#endif
        Log.iprint("computed l2 hash = ");
        Log.println(hash);

        int ret = verifySignature(Slots[CertificateSlotIdx].getLeafCert(),
                                  resp.SignatureVector, hash);
        SPDMCPP_LOG_TRACE_RS(Log, ret);
        if (!ret)
        {
            Log.iprintln("measurements SIGNATURE verify PASSED!");
            markInfo(ConnectionInfoEnum::MEASUREMENTS);
        }
        else
        {
            mbedtlsPrintErrorLine(Log, "mbedtls_ecdsa_verify()", ret);
            return RetStat::ERROR_MEASUREMENT_SIGNATURE_VERIFIY_FAILED;
        }
    }
    else
    {
        appendRecvToBuf(BufEnum::L);

        SPDMCPP_ASSERT(MeasurementIndices.any());
        uint8_t idx = getFirstMeasurementIndex();
        MeasurementIndices.reset(idx);
        return tryGetMeasurements(idx);
    }
    return rs;
}

RetStat ConnectionClass::handleRecv()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);

    clearTimeout();

    Log.iprint("ResponseBuffer.size() = ");
    Log.println(ResponseBuffer.size());
    Log.iprint("ResponseBuffer = ");
    Log.println(ResponseBuffer);

    RequestResponseEnum code = RequestResponseEnum::INVALID;
    {
        TransportClass::LayerState lay; // TODO double decode
        if (Transport)
        {
            auto rs = Transport->decode(ResponseBuffer, lay);
            SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);
        }
        ResponseBufferSPDMOffset = lay.getEndOffset();
        code = packetMessageHeaderGetRequestresponsecode(
            ResponseBuffer.data() + ResponseBufferSPDMOffset);
    }

    if (code == RequestResponseEnum::RESPONSE_ERROR)
    {
        Log.iprint("RESPONSE_ERROR while waiting for response: ");
        Log.println(WaitingForResponse);
        WaitingForResponse = RequestResponseEnum::INVALID;

        PacketErrorResponseVar err;
        auto rs = interpretResponse(err);
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
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DTYPE(type)                                                            \
    case type::requestResponseCode:                                            \
        rs = handleRecv<type>();                                               \
        break;
        DTYPE(PacketVersionResponseVar)
        DTYPE(PacketCapabilitiesResponse)
        DTYPE(PacketAlgorithmsResponseVar)
        DTYPE(PacketDigestsResponseVar)
        DTYPE(PacketCertificateResponseVar)
        DTYPE(PacketChallengeAuthResponseVar)
        DTYPE(PacketMeasurementsResponseVar)
        default:
            Log.iprint("!!! Unknown code: ");
            Log.println(code);
            return RetStat::ERROR_UNKNOWN_REQUEST_RESPONSE_CODE;
    }
#undef DTYPE
    SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);
    return rs;
}

RetStat ConnectionClass::handleTimeout()
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    if (SendRetry)
    {
        --SendRetry;
        auto rs = Context->IO->write(SendBuffer);
        SPDMCPP_CONNECTION_RS_ERROR_RETURN(rs);

        rs = Transport->setupTimeout(SendTimeout);
        SPDMCPP_LOG_TRACE_RS(Log, rs);
        return rs;
    }
    WaitingForResponse = RequestResponseEnum::INVALID;
    return RetStat::ERROR_TIMEOUT;
}

void ConnectionClass::clearTimeout()
{
    if (Transport)
    {
        Transport->clearTimeout();
    }
    SendTimeout = 0;
    SendRetry = 0;
}

} // namespace spdmcpp

#undef SPDMCPP_CONNECTION_RS_ERROR_RETURN
