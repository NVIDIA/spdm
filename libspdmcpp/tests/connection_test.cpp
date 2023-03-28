
#include "test_helpers.hpp"

#include <spdmcpp/common.hpp>
#include <spdmcpp/connection.hpp>
#include <spdmcpp/context.hpp>
#include <spdmcpp/mbedtls_support.hpp>
#include <spdmcpp/mctp_support.hpp>
#include <spdmcpp/packet.hpp>

#include <array>
#include <cstring>
#include <list>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace spdmcpp;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ASSERT_MBEDTLS_0(call)                                                 \
    if (int _ret = (call))                                                     \
    {                                                                          \
        mbedtlsPrintErrorLine(log, #call, _ret);                               \
        ASSERT_EQ(_ret, 0);                                                    \
    }

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define EXPECT_FLAG_SET(value, flag) EXPECT_EQ((value) & (flag), (flag))

class FixtureTransportClass : public MctpTransportClass
{
  public:
    FixtureTransportClass() : MctpTransportClass(14)
    {}

    spdmcpp::RetStat setupTimeout(spdmcpp::timeout_us_t /*timeout*/) override
    {
        return RetStat::OK;
    }
};

class FixtureIOClass : public IOClass
{
  public:
    RetStat write(const std::vector<uint8_t>& buf,
                  timeout_us_t /*timeout*/ = timeoutUsInfinite) override
    {
        WriteQueue.push_back(buf);
        return RetStat::OK;
    }
    RetStat read(std::vector<uint8_t>& buf,
                 timeout_us_t /*timeout*/ = timeoutUsInfinite) override
    {
        if (ReadQueue.empty())
        {
            return RetStat::ERROR_UNKNOWN;
        }
        std::swap(buf, ReadQueue.front());
        ReadQueue.pop_front();
        return RetStat::OK;
    }

    std::list<std::vector<uint8_t>> WriteQueue;
    std::list<std::vector<uint8_t>> ReadQueue;
    size_t ReadIndex = 0;
};

enum class MessageHashEnum : uint8_t
{
    M,
    L,
    NUM
};

// NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class ConnectionFixture
{
  public:
    LogClass log;
    FixtureIOClass IO;
    FixtureTransportClass Trans;
    ContextClass Context;
    ConnectionClass Connection;

    ConnectionFixture() : log(std::cout), Connection(Context, log, 0,  spdmcpp::TransportMedium::PCIe)
    {
        Context.registerIo(IO, spdmcpp::TransportMedium::PCIe);
        Connection.registerTransport(Trans);
    }
    ~ConnectionFixture()
    {
        try
        {
            Connection.unregisterTransport(Trans);
            Context.unregisterIo(IO, spdmcpp::TransportMedium::PCIe );
        }
        catch(const std::exception& exc)
        {
            SPDMCPP_ASSERT(false);
        }
    }

    HashClass& getHash(MessageHashEnum hashidx)
    {
        SPDMCPP_ASSERT(hashidx < MessageHashEnum::NUM);
        return Hashes[static_cast<size_t>(hashidx)];
    }

    template <typename T, typename... Targs>
    RetStat interpret(T& packet, Targs... fargs,
                      MessageHashEnum hashidx = MessageHashEnum::NUM)
    {
        LogClass log(std::cerr);
        SPDMCPP_ASSERT(IO.WriteQueue.size() == 1);
        auto& buf = IO.WriteQueue.front();

        TransportClass::LayerState lay;

        auto rs = Trans.decode(buf, lay);
        SPDMCPP_LOG_TRACE_RS(Connection.getLog(), rs);
        if (rs != RetStat::OK)
        {
            return rs;
        }
        size_t off = lay.getEndOffset();
        if (hashidx < MessageHashEnum::NUM)
        {
            getHash(hashidx).update(buf, off);
        }
        rs = packetDecode(log, packet, buf, off, fargs...);
        SPDMCPP_LOG_TRACE_RS(Connection.getLog(), rs);
        if (rs == RetStat::OK)
        {
            SPDMCPP_ASSERT(off == buf.size());
            IO.WriteQueue.pop_front();
        }
        return rs;
    }

    template <typename T>
    RetStat push(T& packet, MessageHashEnum hashidx = MessageHashEnum::NUM)
    {
        IO.ReadQueue.emplace_back();

        std::vector<uint8_t>& buf = IO.ReadQueue.back();
        buf.clear();
        TransportClass::LayerState lay;

        Trans.encodePre(buf, lay);

        size_t start = lay.getEndOffset();
        size_t off = start;
        auto rs = packetEncode(packet, buf, off);
        if (isError(rs))
        {
            IO.ReadQueue.pop_back();
            return rs;
        }
        if (hashidx < MessageHashEnum::NUM)
        {
            getHash(hashidx).update(buf, start);
        }
        Trans.encodePost(buf, lay);

        return rs;
    }

    RetStat handleRecv()
    {
        std::vector<uint8_t> buf;
        IO.read(buf);
        EventReceiveClass ev(buf);
        return Connection.handleEvent(ev);
    }

  private:
    std::array<HashClass, static_cast<size_t>(MessageHashEnum::NUM)> Hashes;
};

void testConnectionFlow(BaseAsymAlgoFlags asymAlgo, BaseHashAlgoFlags hashAlgo)
{
    ConnectionFixture fix;

    fix.Connection.refreshMeasurements(0);

    LogClass& log = fix.Connection.getLog();
    PacketAlgorithmsResponseVar algoResp;
    algoResp.Min.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;

    algoResp.Min.BaseAsymAlgo = asymAlgo;
    algoResp.Min.BaseHashAlgo = hashAlgo;
    algoResp.Min.MeasurementHashAlgo =
        MeasurementHashAlgoFlags::TPM_ALG_SHA_512;

    ASSERT_EQ(countBits(algoResp.Min.BaseAsymAlgo), 1);
    ASSERT_EQ(countBits(algoResp.Min.BaseHashAlgo), 1);

    fix.getHash(MessageHashEnum::L).setup(toHash(algoResp.Min.BaseHashAlgo));
    fix.getHash(MessageHashEnum::M).setup(toHash(algoResp.Min.BaseHashAlgo));

    {
        PacketGetVersionRequest req;
        auto rs = fix.interpret(req, MessageHashEnum::M);
        ASSERT_EQ(rs, RetStat::OK);
    }
    {
        PacketVersionResponseVar resp;
        resp.Min.Header.MessageVersion = MessageVersionEnum::SPDM_1_0;
        PacketVersionNumber ver;
        ver.setMajor(1);
        ver.setMinor(1);
        resp.VersionNumberEntries.push_back(ver);
        auto rs = fix.push(resp, MessageHashEnum::M);
        ASSERT_EQ(rs, RetStat::OK);
        rs = fix.handleRecv();
        ASSERT_EQ(rs, RetStat::OK);
    }
    {
        PacketGetCapabilitiesRequest req;
        auto rs = fix.interpret(req, MessageHashEnum::M);
        ASSERT_EQ(rs, RetStat::OK);
    }
    {
        PacketCapabilitiesResponse resp;
        resp.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;
        resp.Flags = ResponderCapabilitiesFlags::CERT_CAP |
                     ResponderCapabilitiesFlags::CHAL_CAP |
                     ResponderCapabilitiesFlags::MEAS_CAP_10;

        auto rs = fix.push(resp, MessageHashEnum::M);
        ASSERT_EQ(rs, RetStat::OK);
        rs = fix.handleRecv();
        ASSERT_EQ(rs, RetStat::OK);
    }
    {
        PacketNegotiateAlgorithmsRequestVar req;
        auto rs = fix.interpret(req, MessageHashEnum::M);
        ASSERT_EQ(rs, RetStat::OK);
        EXPECT_FLAG_SET(req.Min.BaseAsymAlgo,
                        BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P256);
        EXPECT_FLAG_SET(req.Min.BaseHashAlgo,
                        BaseHashAlgoFlags::TPM_ALG_SHA_384);
    }

    PacketDecodeInfo info;
    int fsize = getHashSize(algoResp.Min.BaseHashAlgo);
    ASSERT_NE(fsize, invalidFlagSize);
    info.BaseHashSize = fsize;
    fsize = getSignatureSize(algoResp.Min.BaseAsymAlgo);
    ASSERT_NE(fsize, invalidFlagSize);
    info.SignatureSize = fsize;

    mbedtls_pk_context pkctx;
    mbedtls_pk_init(&pkctx);

    mbedtls_x509_crt caCert;
    mbedtls_x509_crt_init(&caCert);
    {
        ASSERT_MBEDTLS_0(mbedtls_pk_setup(
            &pkctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)));
        auto* ctx = mbedtls_pk_ec(pkctx);
        ASSERT_MBEDTLS_0(mbedtls_ecdsa_genkey(
            ctx, toMbedtlsGroupID(toSignature(algoResp.Min.BaseAsymAlgo)), fRng,
            nullptr));
    }
    {
        mbedtls_x509write_cert ctx;
        mbedtls_x509write_crt_init(&ctx);

        mbedtls_x509write_crt_set_version(&ctx, 3 - 1);
        mbedtls_x509write_crt_set_issuer_key(&ctx, &pkctx);
        mbedtls_x509write_crt_set_subject_key(&ctx, &pkctx);
        mbedtls_x509write_crt_set_issuer_name(&ctx, "CN=CA,O=mbed TLS,C=UK");

        mbedtls_x509write_crt_set_validity(&ctx, "20010101000000",
                                           "20301231235959");

        mbedtls_x509write_crt_set_md_alg(
            &ctx, toMbedtls(toHash(algoResp.Min.BaseHashAlgo)));

        std::vector<uint8_t> buf;
        buf.resize(1024);

        log.iprint("der: ");
        log.print(buf);
        int ret = mbedtls_x509write_crt_der(&ctx, buf.data(), buf.size(), fRng,
                                            nullptr);
        if (ret < 0)
        {
            mbedtlsPrintErrorLine(log, "mbedtls_x509write_crt_der()", ret);
        }
        log.iprint("mbedtls_x509write_crt_der(): ");
        log.println(ret);

        ASSERT_MBEDTLS_0(mbedtls_x509_crt_parse_der(
            &caCert, &*std::prev(buf.end(), ret), ret));
        mbedtls_x509write_crt_free(&ctx);
    }

    PacketDigestsResponseVar digestResp;
    digestResp.Min.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;
    PacketCertificateResponseVar certResp;
    certResp.Min.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;

    {
        std::vector<uint8_t>& certBuf = certResp.CertificateVector;
        certBuf.resize(sizeof(PacketCertificateChain));

        std::vector<uint8_t> rootCert(caCert.raw.len);
        // NOLINTNEXTLINE cppcoreguidelines-pro-bounds-pointer-arithmetic
        std::copy(caCert.raw.p, caCert.raw.p + caCert.raw.len,
                  rootCert.begin());

        std::vector<uint8_t> rootCertHash;
        HashClass::compute(rootCertHash, toHash(algoResp.Min.BaseHashAlgo),
                           rootCert);

        std::copy(rootCertHash.begin(), rootCertHash.end(),
                  std::back_inserter(certBuf));
        std::copy(rootCert.begin(), rootCert.end(),
                  std::back_inserter(certBuf));
        {
            PacketCertificateChain chain;
            chain.Length = certBuf.size();
            size_t off = 0;
            ASSERT_EQ(packetEncodeInternal(chain, certBuf, off), RetStat::OK);
        }
        std::vector<uint8_t>& digest = digestResp.Digests[0];
        digest.resize(info.BaseHashSize);
        HashClass::compute(digest, toHash(algoResp.Min.BaseHashAlgo), certBuf);
    }

    {
        auto rs = fix.push(algoResp, MessageHashEnum::M);
        ASSERT_EQ(rs, RetStat::OK);
        rs = fix.handleRecv();
        ASSERT_EQ(rs, RetStat::OK);
    }
    {
        PacketGetDigestsRequest req;
        auto rs = fix.interpret(req, MessageHashEnum::M);
        ASSERT_EQ(rs, RetStat::OK);
    }
    {
        digestResp.finalize();

        auto rs = fix.push(digestResp, MessageHashEnum::M);
        ASSERT_EQ(rs, RetStat::OK);
        rs = fix.handleRecv();
        ASSERT_EQ(rs, RetStat::OK);
    }
    {
        PacketGetCertificateRequest req;
        auto rs = fix.interpret(req, MessageHashEnum::M);
        ASSERT_EQ(rs, RetStat::OK);
    }
    {
        certResp.finalize();

        auto rs = fix.push(certResp, MessageHashEnum::M);
        ASSERT_EQ(rs, RetStat::OK);
        rs = fix.handleRecv();
        ASSERT_EQ(rs, RetStat::OK);
    }
    {
        PacketChallengeRequest req;
        auto rs = fix.interpret(req, MessageHashEnum::M);
        ASSERT_EQ(rs, RetStat::OK);

        PacketChallengeAuthResponseVar resp;
        resp.Min.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;
        resp.Min.Header.Param2 = 1;
        fillPseudoRandom(resp.Nonce);

        resp.CertChainHashVector = digestResp.Digests[0];

        resp.MeasurementSummaryHashVector.resize(info.BaseHashSize);
        fillPseudoRandom(resp.MeasurementSummaryHashVector);

        {
            resp.finalize();
            auto& hc = fix.getHash(MessageHashEnum::M);
            {
                std::vector<uint8_t> buf;
                ASSERT_EQ(packetEncode(resp, buf), RetStat::OK);
                hc.update(buf);
            }
            std::vector<uint8_t> hash;
            hc.hashFinish(hash);

            log.iprint("TEST M1/M2 hash: ");
            log.println(hash);

            ASSERT_MBEDTLS_0(
                computeSignature(&pkctx, resp.SignatureVector, hash));
        }

        resp.finalize();

        rs = fix.push(resp);
        ASSERT_EQ(rs, RetStat::OK);
        rs = fix.handleRecv();
        ASSERT_EQ(rs, RetStat::OK);
    }
    {
        PacketGetMeasurementsRequestVar req;
        auto rs = fix.interpret(req, MessageHashEnum::L);
        ASSERT_EQ(rs, RetStat::OK);

        EXPECT_EQ(req.Min.Header.Param1, 1);
        EXPECT_EQ(req.Min.Header.Param2, 0xFF);
        EXPECT_EQ(req.SlotIDParam, 0);
        // TODO validate req.Nonce is not 0 or the requested Nonce

        PacketMeasurementsResponseVar resp;
        resp.Min.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;

        // prepare measurements
        { // TODO refactor to helper, and add more!
            PacketMeasurementBlockVar block;
            block.Min.Index = 1;
            block.Min.MeasurementSpecification = 1;
            {
                PacketMeasurementFieldVar field;
                field.Min.Type = 0x80; // Raw bit stream & Immutable ROM
                field.ValueVector.resize(127);
                fillPseudoRandom(field.ValueVector);

                ASSERT_EQ(field.finalize(), RetStat::OK);
                ASSERT_EQ(packetEncode(field, block.MeasurementVector),
                          RetStat::OK);
            }
            ASSERT_EQ(block.finalize(), RetStat::OK);
            resp.MeasurementBlockVector.emplace_back(block);
        }

        fillPseudoRandom(resp.Nonce);
        {
            resp.finalize();
            auto& hc = fix.getHash(MessageHashEnum::L);
            {
                std::vector<uint8_t> buf;
                ASSERT_EQ(packetEncode(resp, buf), RetStat::OK);
                hc.update(buf);
            }
            std::vector<uint8_t> hash;
            hc.hashFinish(hash);

            log.iprint("TEST L1/L2 hash: ");
            log.println(hash);

            ASSERT_MBEDTLS_0(
                computeSignature(&pkctx, resp.SignatureVector, hash));
        }

        resp.finalize();

        rs = fix.push(resp);
        ASSERT_EQ(rs, RetStat::OK);
        rs = fix.handleRecv();
        ASSERT_EQ(rs, RetStat::OK);
    }

    mbedtls_x509_crt_free(&caCert);
    mbedtls_pk_free(&pkctx);
}

TEST(Connection, FullFlow_ECDSA_256_SHA_256)
{
    testConnectionFlow(BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P256,
                       BaseHashAlgoFlags::TPM_ALG_SHA_256);
}

TEST(Connection, FullFlow_ECDSA_256_SHA_384)
{
    testConnectionFlow(BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P256,
                       BaseHashAlgoFlags::TPM_ALG_SHA_384);
}

TEST(Connection, FullFlow_ECDSA_256_SHA_512)
{
    testConnectionFlow(BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P256,
                       BaseHashAlgoFlags::TPM_ALG_SHA_512);
}

TEST(Connection, FullFlow_ECDSA_384_SHA_384)
{
    testConnectionFlow(BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P384,
                       BaseHashAlgoFlags::TPM_ALG_SHA_384);
}

TEST(Connection, FullFlow_ECDSA_521_SHA_512)
{
    testConnectionFlow(BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P521,
                       BaseHashAlgoFlags::TPM_ALG_SHA_512);
}
