/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "spdm_fuzzer_responder.hpp"

#include "spdmcpp/enum_defs.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <ostream>
#include <span>
#include <vector>

#ifndef LOCAL_ASSERT_EQ
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define LOCAL_ASSERT_EQ(val1, val2)                                            \
    if ((val1) != (val2))                                                      \
    {                                                                          \
        flowResult = false;                                                    \
        log.print("Fuzzing fail in line ");                                    \
        log.print(__LINE__);                                                   \
        log.print(" Expected different value: ");                              \
        log.print(" " #val1 " (");                                             \
        log.print(val1);                                                       \
        log.print(") != " #val2 " (");                                         \
        log.print(val2);                                                       \
        log.println(") ... Exit");                                             \
        break;                                                                 \
    }
#endif /*LOCAL_ASSERT_EQ*/

#ifndef LOCAL_EXPECT_EQ
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define LOCAL_EXPECT_EQ(val1, val2)                                            \
    if ((val1) != (val2))                                                      \
    {                                                                          \
        flowResult = false;                                                    \
        log.print("Fuzzing problem in line ");                                 \
        log.print(__LINE__);                                                   \
        log.print("Expected different value: ");                               \
        log.print(": " #val1 " (");                                            \
        log.print(val1);                                                       \
        log.print(") != " #val2 " (");                                         \
        log.print(val2);                                                       \
        log.println(")");                                                      \
    }
#endif /*LOCAL_EXPECT_EQ*/

#ifndef LOCAL_ASSERT_MBEDTLS_0
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define LOCAL_ASSERT_MBEDTLS_0(call)                                           \
    if (int _ret = (call))                                                     \
    {                                                                          \
        mbedtlsPrintErrorLine(log, #call, _ret);                               \
        LOCAL_ASSERT_EQ(_ret, 0);                                              \
    }
#endif

namespace spdm_wrapper
{

HashClass& FuzzingResponder::getHash(MessageHashEnum hashIdx)
{
    SPDMCPP_ASSERT(hashIdx < MessageHashEnum::NUM);
    return Hashes[static_cast<size_t>(hashIdx)];
}

RetStat FuzzingResponder::sendRandomData(MessageHashEnum hashIdx)
{
    TransportClass::LayerState lay;
    std::vector<uint8_t> buf;

    trans.encodePre(buf, lay);
    size_t start = lay.getEndOffset();

    char size{};
    if (!std::cin.get(size))
    {
        return RetStat::ERROR_UNKNOWN;
    }
    char tmp{};
    for (int i = 0; i < size; i++)
    {
        if (!std::cin.get(tmp))
        {
            return RetStat::ERROR_UNKNOWN;
        }
        buf.push_back(tmp);
    }

    if (hashIdx < MessageHashEnum::NUM)
    {
        if (auto rs = getHash(hashIdx).update(buf, start); rs != RetStat::OK)
        {
            return rs;
        }
    }
    trans.encodePost(buf, lay);

    io.write(buf);
    return RetStat::OK;
}

bool FuzzingResponder::sendPreparedResponse(RequestResponseEnum msgType,
                                            MessageHashEnum hashIdx, int msgIdx)
{
    TransportClass::LayerState lay;
    std::vector<uint8_t> buf;

    trans.encodePre(buf, lay);
    size_t start = lay.getEndOffset();

    std::vector<uint8_t> buf2 =
        predefinedResponses.getResponse(static_cast<uint8_t>(msgType), msgIdx);
    if (buf2.size() == 0)
    {
        // abort();
        return false;
    }

    buf.insert(std::end(buf), std::begin(buf2), std::end(buf2));

    if (hashIdx < MessageHashEnum::NUM)
    {
        if (getHash(hashIdx).update(buf, start) != RetStat::OK)
        {
            return false;
        }
    }
    trans.encodePost(buf, lay);

    io.write(buf);
    return true;
}

void FuzzingResponder::resetState()
{
    getHash(MessageHashEnum::L).setup(toHash(algoResp.Min.BaseHashAlgo));
    getHash(MessageHashEnum::M).setup(toHash(algoResp.Min.BaseHashAlgo));

    info.BaseHashSize = getHashSize(algoResp.Min.BaseHashAlgo);
    info.SignatureSize = getSignatureSize(algoResp.Min.BaseAsymAlgo);

    prepareDefaultResponses();
}

RetStat FuzzingResponder::updateHash(MessageHashEnum hashIdx)
{
    // SPDMCPP_ASSERT(IO.WriteQueue.size() == 1);

    std::vector<uint8_t> buf;
    auto rs = io.read(buf);
    if (rs != RetStat::OK)
    {
        return rs;
    }
    TransportClass::LayerState lay;

    rs = trans.decode(buf, lay);
    SPDMCPP_LOG_TRACE_RS(log, rs);
    if (rs != RetStat::OK)
    {
        return rs;
    }
    size_t off = lay.getEndOffset();
    if (hashIdx < MessageHashEnum::NUM)
    {
        rs = getHash(hashIdx).update(buf, off);
    }
    return rs;
}

void FuzzingResponder::prepareDefaultResponses()
{
    algoResp.Min.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;
    algoResp.Min.BaseAsymAlgo = asymAlgo;
    algoResp.Min.BaseHashAlgo = hashAlgo;
    algoResp.Min.MeasurementHashAlgo =
        MeasurementHashAlgoFlags::TPM_ALG_SHA_512;
}

bool FuzzingResponder::sendResponse(RequestResponseEnum expectedResponse,
                                    bool& modified)
{
    static int certRespIdx;
    static int measurementRespIdx;
    modified = false;
    bool flowResult = true;
    switch (expectedResponse)
    {
        case RequestResponseEnum::RESPONSE_VERSION:
        {
            certRespIdx = 0;
            measurementRespIdx = 0;

            PacketVersionResponseVar resp;
            resp.Min.Header.MessageVersion = MessageVersionEnum::SPDM_1_0;
            PacketVersionNumber ver;
            ver.setMajor(1);
            ver.setMinor(1);
            resp.VersionNumberEntries.push_back(ver);
            // NOLINTNEXTLINE(modernize-avoid-bind)
            auto fuzzingFunction =
                std::bind(&FuzzingResponder::fuzzResponseMessageVersion, this,
                          std::placeholders::_1);
            modified = sendResponseBySource<PacketVersionResponseVar>(
                resp, fuzzingFunction, config.fuseThrRespMessages.version, 0,
                MessageHashEnum::M);
        }
        break;

        case RequestResponseEnum::RESPONSE_CAPABILITIES:
        {
            updateHash(MessageHashEnum::M);

            PacketCapabilitiesResponse resp;
            resp.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;
            resp.Flags = ResponderCapabilitiesFlags::CERT_CAP |
                         ResponderCapabilitiesFlags::CHAL_CAP |
                         ResponderCapabilitiesFlags::MEAS_CAP_10;

            // NOLINTNEXTLINE(modernize-avoid-bind)
            auto fuzzingFunction =
                std::bind(&FuzzingResponder::fuzzResponseMessageCapabilities,
                          this, std::placeholders::_1);
            modified = sendResponseBySource<PacketCapabilitiesResponse>(
                resp, fuzzingFunction, config.fuseThrRespMessages.capability, 0,
                MessageHashEnum::M);
        }
        break;

        case RequestResponseEnum::RESPONSE_ALGORITHMS:
        {
            updateHash(MessageHashEnum::M);

            {
                if (mbedtls_pk_setup(&pkctx, mbedtls_pk_info_from_type(
                                                 MBEDTLS_PK_ECKEY)) != 0)
                {
                    log.println(
                        "!!!! Error mbedtls_pk_setup returned non 0 value");
                }
                mbedtls_ecp_keypair* ctx = mbedtls_pk_ec(pkctx);
                if (mbedtls_ecdsa_genkey(ctx,
                                         toMbedtlsGroupID(toSignature(
                                             algoResp.Min.BaseAsymAlgo)),
                                         fRng, nullptr) != 0)
                {
                    log.println("!!!! Error returned non 0 value");
                }
            }
            {
                mbedtls_x509write_cert ctx;
                mbedtls_x509write_crt_init(&ctx);

                mbedtls_x509write_crt_set_version(&ctx, 3 - 1);
                mbedtls_x509write_crt_set_issuer_key(&ctx, &pkctx);
                mbedtls_x509write_crt_set_subject_key(&ctx, &pkctx);
                mbedtls_x509write_crt_set_issuer_name(&ctx,
                                                      "CN=CA,O=mbed TLS,C=UK");
                mbedtls_x509write_crt_set_validity(&ctx, "20010101000000",
                                                   "20301231235959");
                mbedtls_x509write_crt_set_md_alg(
                    &ctx, toMbedtls(toHash(algoResp.Min.BaseHashAlgo)));

                std::vector<uint8_t> buf;
                buf.resize(1024);
                std::fill(buf.begin(), buf.end(), 0);

                int ret = mbedtls_x509write_crt_der(&ctx, buf.data(),
                                                    buf.size(), fRng, nullptr);

                if (ret < 0)
                {
                    mbedtlsPrintErrorLine(log, "mbedtls_x509write_crt_der()",
                                          ret);
                }
                else
                {
                    std::span<const uint8_t, std::dynamic_extent> bufDer(
                        std::prev(buf.end(), ret), std::end(buf));
                    log.println("mbedtls_x509write_crt_der() len: ", ret,
                                ", der: ", bufDer);
                }

                LOCAL_ASSERT_MBEDTLS_0(mbedtls_x509_crt_parse_der(
                    &caCert, &*std::prev(buf.end(), ret), ret));
                mbedtls_x509write_crt_free(&ctx);
            }
            {
                digestResp.Min.Header.MessageVersion =
                    MessageVersionEnum::SPDM_1_1;
                certResp.Min.Header.MessageVersion =
                    MessageVersionEnum::SPDM_1_1;

                {
                    std::vector<uint8_t>& certBuf = certResp.CertificateVector;
                    certBuf.resize(sizeof(PacketCertificateChain));

                    std::vector<uint8_t> rootCert(caCert.raw.len);
                    // NOLINTNEXTLINE
                    // cppcoreguidelines-pro-bounds-pointer-arithmetic
                    std::copy(caCert.raw.p, caCert.raw.p + caCert.raw.len,
                              rootCert.begin());

                    std::vector<uint8_t> rootCertHash;
                    HashClass::compute(rootCertHash,
                                       toHash(algoResp.Min.BaseHashAlgo),
                                       rootCert);

                    std::copy(rootCertHash.begin(), rootCertHash.end(),
                              std::back_inserter(certBuf));
                    std::copy(rootCert.begin(), rootCert.end(),
                              std::back_inserter(certBuf));
                    {
                        PacketCertificateChain chain;
                        chain.Length = certBuf.size();
                        size_t off = 0;
                        LOCAL_ASSERT_EQ(
                            packetEncodeInternal(chain, certBuf, off),
                            RetStat::OK);
                    }
                    std::vector<uint8_t>& digest = digestResp.Digests[0];
                    digest.resize(info.BaseHashSize);
                    HashClass::compute(
                        digest, toHash(algoResp.Min.BaseHashAlgo), certBuf);
                }
                // NOLINTNEXTLINE(modernize-avoid-bind)
                auto fuzzingFunction =
                    std::bind(&FuzzingResponder::fuzzResponseMessageAlgorithms,
                              this, std::placeholders::_1);
                modified = sendResponseBySource<PacketAlgorithmsResponseVar>(
                    algoResp, fuzzingFunction,
                    config.fuseThrRespMessages.algorithms, 0,
                    MessageHashEnum::M);
            }
        }
        break;

        case RequestResponseEnum::RESPONSE_DIGESTS:
        {
            updateHash(MessageHashEnum::M);
            digestResp.finalize();
            // sendMessage(digestResp, MessageHashEnum::M);
            //  NOLINTNEXTLINE(modernize-avoid-bind)
            auto fuzzingFunction =
                std::bind(&FuzzingResponder::fuzzResponseMessageDigest, this,
                          std::placeholders::_1);
            modified = sendResponseBySource<PacketDigestsResponseVar>(
                digestResp, fuzzingFunction, config.fuseThrRespMessages.digests,
                0, MessageHashEnum::M);
        }
        break;

        case RequestResponseEnum::RESPONSE_CERTIFICATE:
        {
            std::cerr << "Sending cert response" << std::endl;
            updateHash(MessageHashEnum::M);
            certResp.finalize();
            // sendMessage(certResp, MessageHashEnum::M);
            //  NOLINTNEXTLINE(modernize-avoid-bind)
            auto fuzzingFunction =
                std::bind(&FuzzingResponder::fuzzResponseMessageCertificate,
                          this, std::placeholders::_1);
            modified = sendResponseBySource<PacketCertificateResponseVar>(
                certResp, fuzzingFunction,
                config.fuseThrRespMessages.certificate, certRespIdx++,
                MessageHashEnum::M);
        }
        break;

        case RequestResponseEnum::RESPONSE_CHALLENGE_AUTH:
        {
            updateHash(MessageHashEnum::M);

            PacketChallengeAuthResponseVar resp;
            resp.Min.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;
            resp.Min.Header.Param2 = 1;
            fillPseudoRandom(resp.Nonce);

            resp.CertChainHashVector = digestResp.Digests[0];

            resp.MeasurementSummaryHashVector.resize(info.BaseHashSize);
            fillPseudoRandom(resp.MeasurementSummaryHashVector);

            {
                resp.finalize();
                auto& hc = getHash(MessageHashEnum::M);
                {
                    std::vector<uint8_t> buf;
                    LOCAL_ASSERT_EQ(packetEncode(resp, buf), RetStat::OK);
                    LOCAL_ASSERT_EQ(hc.update(buf), RetStat::OK);
                }
                std::vector<uint8_t> hash;
                hc.hashFinish(hash);

                log.iprint("TEST M1/M2 hash: ");
                log.println(hash);

                LOCAL_ASSERT_MBEDTLS_0(
                    this->computeSignature(&pkctx, resp.SignatureVector, hash));
            }

            resp.finalize();
            // sendMessage(resp);
            //  NOLINTNEXTLINE(modernize-avoid-bind)
            auto fuzzingFunction =
                std::bind(&FuzzingResponder::fuzzResponseMessageChallengeAuth,
                          this, std::placeholders::_1);
            modified = sendResponseBySource<PacketChallengeAuthResponseVar>(
                resp, fuzzingFunction, config.fuseThrRespMessages.challengeAuth,
                0);
            break;
        }

        case RequestResponseEnum::RESPONSE_MEASUREMENTS:
        {
            updateHash(MessageHashEnum::L);

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

                    LOCAL_ASSERT_EQ(field.finalize(), RetStat::OK);
                    LOCAL_ASSERT_EQ(
                        packetEncode(field, block.MeasurementVector),
                        RetStat::OK);
                }
                LOCAL_ASSERT_EQ(block.finalize(), RetStat::OK);
                resp.MeasurementBlockVector.emplace_back(block);
            }

            fillPseudoRandom(resp.Nonce);
            {
                resp.finalize();
                auto& hc = getHash(MessageHashEnum::L);
                {
                    std::vector<uint8_t> buf;
                    LOCAL_ASSERT_EQ(packetEncode(resp, buf), RetStat::OK);
                    LOCAL_ASSERT_EQ(hc.update(buf), RetStat::OK);
                }
                std::vector<uint8_t> hash;
                hc.hashFinish(hash);

                log.iprint("TEST L1/L2 hash: ");
                log.println(hash);

                LOCAL_ASSERT_MBEDTLS_0(
                    computeSignature(&pkctx, resp.SignatureVector, hash));
            }

            resp.finalize();

            // sendMessage(resp);
            //  NOLINTNEXTLINE(modernize-avoid-bind)
            auto fuzzingFunction =
                std::bind(&FuzzingResponder::fuzzResponseMessageMeasurements,
                          this, std::placeholders::_1);
            modified = sendResponseBySource<PacketMeasurementsResponseVar>(
                resp, fuzzingFunction, config.fuseThrRespMessages.measurements,
                measurementRespIdx);

            break;
        }

        default:
            log.print("Wrong connection state = ");
            log.print(expectedResponse);
            log.println(__LINE__);
            flowResult = false;
            break;
    }
    return flowResult;
}

bool FuzzingResponder::doRandomize(WrapperConfig::Threshold threshold)
{
    if (!threshold.enabled)
    {
        return false;
    }
    uint32_t tmp = 0;
    getFuzzingData(tmp);
    return threshold <= tmp;
}

/**
 * @brief Fuzes response messages' header. Data is altered according to read
 *        instructions. First byte (in instruction stream) contain value that
 *        is compared with threshold in order to decide if fuze header or not.
 *        Regardless of the result the same number od bytes is read.
 * @param header struct with parsed data before serialization
 * @return true is header was modified
 * @return false header wasn't modified
 */
bool FuzzingResponder::fuzzMsgHeader(PacketMessageHeader& header, bool doAlter)
{
    bool result = false;
    uint32_t randWord{};
    if (getFuzzingData(randWord) && config.alterHeaderThr.all <= randWord)
    {
        ;
    }
    else
    {
        doAlter = false;
    }

    if (getFuzzingData(randWord) && doAlter &&
        config.alterHeaderThr.version <= randWord)
    {
        result = true;
        getFuzzingData(randWord);
        header.MessageVersion = static_cast<MessageVersionEnum>(randWord);
    }
    else
    {
        dropFuzzingData(1);
    }

    if (getFuzzingData(randWord) && doAlter &&
        config.alterHeaderThr.messageType <= randWord)
    {
        result = true;
        getFuzzingData(randWord);
        header.requestResponseCode = static_cast<RequestResponseEnum>(randWord);
    }
    else
    {
        dropFuzzingData(1);
    }

    if (getFuzzingData(randWord) && doAlter &&
        config.alterHeaderThr.param <= randWord)
    {
        result = true;
        getFuzzingData(header.Param1);
    }
    else
    {
        dropFuzzingData(1);
    }

    if (getFuzzingData(randWord) && doAlter &&
        config.alterHeaderThr.param <= randWord)
    {
        result = true;
        getFuzzingData(header.Param2);
    }
    else
    {
        dropFuzzingData(1);
    }
    return result;
}

bool FuzzingResponder::fuzzResponseMessageVersion(PacketVersionResponseVar& msg)
{
    if (!config.fuseThrRespMessages.version.enabled)
    {
        return false; // Fuzing this message is disabled, don't read
                      // instructions
    }

    bool result = false;
    uint8_t randByte{};

    auto fuzzData = getFuzzingData(randByte);
    const bool doAlter =
        (fuzzData && config.fuseThrRespMessages.version <= randByte);
    const bool doAlterData = (doAlter && getFuzzingData(randByte) &&
                              config.alterDataThr <= randByte);

    result = fuzzMsgHeader(msg.Min.Header, doAlter);

    if (doAlterData)
    {
        result = true;
        getFuzzingData(msg.Min.Reserved);
    }
    else
    {
        dropFuzzingData(sizeof(msg.Min.Reserved));
    }

    for (auto& verItem : msg.VersionNumberEntries)
    {
        if (doAlterData)
        {
            result = true;
            getFuzzingData(verItem.Bits);
        }
        else
        {
            dropFuzzingData(sizeof(verItem.Bits));
        }
    }

    return result;
}

bool FuzzingResponder::fuzzResponseMessageCapabilities(
    PacketCapabilitiesResponse& msg)
{
    if (!config.fuseThrRespMessages.capability.enabled)
    {
        return false; // Fuzing this message is disabled, don't read
                      // instructions
    }
    bool result = false;
    uint32_t randByte{};

    const bool doAlter = (getFuzzingData(randByte) &&
                          config.fuseThrRespMessages.capability <= randByte);
    const bool doAlterData = (doAlter && getFuzzingData(randByte) &&
                              config.alterDataThr <= randByte);

    result = fuzzMsgHeader(msg.Header, doAlter);
    if (doAlterData)
    {
        result = true;
        getFuzzingData(msg.Reserved0);
    }
    else
    {
        dropFuzzingData(sizeof(msg.Reserved0));
    }

    if (doAlterData)
    {
        result = true;
        getFuzzingData(msg.CTExponent);
    }
    else
    {
        dropFuzzingData(sizeof(msg.CTExponent));
    }

    if (doAlterData)
    {
        result = true;
        getFuzzingData(msg.Reserved1);
    }
    else
    {
        dropFuzzingData(sizeof(msg.Reserved1));
    }

    if (doAlterData)
    {
        result = true;
        getFuzzingData(randByte);
        msg.Flags = static_cast<ResponderCapabilitiesFlags>(randByte);
    }
    else
    {
        dropFuzzingData(sizeof(randByte));
    }
    return result;
}

bool FuzzingResponder::fuzzResponseMessageAlgorithms(
    PacketAlgorithmsResponseVar& msg)
{
    if (!config.fuseThrRespMessages.algorithms.enabled)
    {
        return false; // Fuzing this message is disabled, don't read
                      // instructions
    }

    bool result = false;
    uint8_t randByte{};

    auto fuzzData = getFuzzingData(randByte);
    const bool doAlter =
        (fuzzData && config.fuseThrRespMessages.algorithms <= randByte);
    const bool doAlterData = (doAlter && getFuzzingData(randByte) &&
                              config.alterDataThr <= randByte);

    result = fuzzMsgHeader(msg.Min.Header, doAlter);

    if (doAlterData)
    {
        result = true;
        getFuzzingData(msg.Min.Reserved0);
        getFuzzingData(msg.Min.Reserved1);
        getFuzzingData(msg.Min.Reserved2);
        getFuzzingData(msg.Min.Reserved3);
        getFuzzingData(msg.Min.Reserved4);
    }
    else
    {
        dropFuzzingData(sizeof(msg.Min.Reserved0));
        dropFuzzingData(sizeof(msg.Min.Reserved1));
        dropFuzzingData(sizeof(msg.Min.Reserved2));
        dropFuzzingData(sizeof(msg.Min.Reserved3));
        dropFuzzingData(sizeof(msg.Min.Reserved4));
    }

    unsigned char vectSize{};
    static constexpr auto vecMax = 16U;

    if (doAlterData)
    {
        result = true;
        getFuzzingData(vectSize);
        vectSize %= vecMax;
    }
    else
    {
        dropFuzzingData(sizeof(vectSize));
    }

    msg.PacketReqAlgVector.resize(vectSize);
    for (auto& alg : msg.PacketReqAlgVector)
    {
        unsigned char randBVal{};
        if (getFuzzingData(randByte) && doAlter &&
            config.alterDataThr <= randByte)
        {
            result = true;
            getFuzzingData(randBVal);
            alg.AlgType = static_cast<AlgTypeEnum>(randBVal);
        }
        else
        {
            dropFuzzingData(sizeof(randBVal));
        }

        unsigned char nAlgCnt{};
        static const auto maxNAlg = alg.AlgSupported.max_size();

        if (doAlterData)
        {
            result = true;
            getFuzzingData(nAlgCnt);
            nAlgCnt %= maxNAlg;
        }
        else
        {
            dropFuzzingData(sizeof(nAlgCnt));
        }

        alg.setFixedAlgCount(nAlgCnt);
        for (int na = 0; na < nAlgCnt; ++na)
        {
            getFuzzingData(alg.AlgSupported[na]);
        }
    }
    return result;
}

bool FuzzingResponder::fuzzResponseMessageDigest(PacketDigestsResponseVar& msg)
{
    if (!config.fuseThrRespMessages.digests.enabled)
    {
        return false; // Fuzing this message is disabled, don't read
                      // instructions
    }

    bool result = false;
    uint8_t randByte{};

    bool doAlter = (getFuzzingData(randByte) &&
                    config.fuseThrRespMessages.digests <= randByte);
    const bool doAlterData = (doAlter && getFuzzingData(randByte) &&
                              config.alterDataThr <= randByte);

    result = fuzzMsgHeader(msg.Min.Header, doAlter);

    for (auto& dig : msg.Digests)
    {
        uint8_t vectSize{};
        // Get the final vector length
        if (doAlterData)
        {
            result = true;
            getFuzzingData(vectSize);
        }
        else
        {
            dropFuzzingData(sizeof(vectSize));
        }
        dig.resize(vectSize);
        for (auto& val : dig)
        {
            if (doAlterData)
            {
                result = true;
                getFuzzingData(val);
            }
            else
            {
                dropFuzzingData(sizeof(val));
            }
        }
    }
    return result;
}

bool FuzzingResponder::fuzzResponseMessageCertificate(
    PacketCertificateResponseVar& msg)
{
    if (!config.fuseThrRespMessages.certificate.enabled)
    {
        return false; // Fuzing this message is disabled, don't read
                      // instructions
    }
    bool result = false;
    uint8_t randByte{};
    auto fuzzData = getFuzzingData(randByte);
    bool doAlter =
        (fuzzData && config.fuseThrRespMessages.certificate <= randByte);

    const bool doAlterData = (doAlter && getFuzzingData(randByte) &&
                              config.alterDataThr <= randByte);

    result = fuzzMsgHeader(msg.Min.Header, doAlter);

    if (doAlterData)
    {
        result = true;
        getFuzzingData(msg.Min.RemainderLength);
    }
    else
    {
        dropFuzzingData(sizeof(msg.Min.RemainderLength));
    }
    if (doAlterData)
    {
        // Get the final vector length
        uint16_t vectSize{};
        if (getFuzzingData(vectSize))
        {
            vectSize &= 0x3ff;
            msg.CertificateVector.resize(vectSize);
            for (auto& val : msg.CertificateVector)
            {
                getFuzzingData(val);
            }
        }
        result = true;
    }
    return result;
}

bool FuzzingResponder::fuzzResponseMessageChallengeAuth(
    PacketChallengeAuthResponseVar& msg)
{
    if (!config.fuseThrRespMessages.challengeAuth.enabled)
    {
        return false; // Fuzing this message is disabled, don't read
                      // instructions
    }
    bool result = false;
    uint32_t randWord{};

    bool doAlter = (getFuzzingData(randWord) &&
                    config.fuseThrRespMessages.measurements <= randWord);

    // Min part
    result = fuzzMsgHeader(msg.Min.Header, doAlter);

    // Variable len part nonce_array_32 Nonce = {0};
    doAlter = (getFuzzingData(randWord) &&
               config.fuseRespChallengeAuthentication.nonce <= randWord);
    for (auto& nonceVal : msg.Nonce)
    {
        getFuzzingData(randWord);
        if (doAlter)
        {
            nonceVal = randWord;
        }
    }

    // Variable len part std::vector<uint8_t> CertChainHashVector;
    doAlter = (getFuzzingData(randWord) &&
               config.fuseRespChallengeAuthentication.hashChain <= randWord);
    getFuzzingData(randWord);
    if (doAlter)
    {
        srand(randWord);
        // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
        if (config.fuseRespChallengeAuthentication.hashChainLen <=
            (uint32_t)rand())
        {

            // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
            uint8_t newLen = rand();
            if (msg.CertChainHashVector.size() != newLen)
            {
                result |= true;
                msg.CertChainHashVector.resize(newLen);
            }
            for (uint8_t& val : msg.CertChainHashVector)
            {

                // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
                if (config.fuseRespChallengeAuthentication.hashChainLen <=
                    (uint32_t)rand())
                {
                    // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
                    uint8_t newVal = rand();
                    result |= (val != newVal);
                    val = newVal;
                }
            }
        }
    }

    // Variable len part std::vector<uint8_t> MeasurementSummaryHashVector;
    doAlter =
        (getFuzzingData(randWord) &&
         config.fuseRespChallengeAuthentication.measurementSummary <= randWord);
    getFuzzingData(randWord);
    if (doAlter)
    {
        srand(randWord);

        // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
        if (config.fuseRespChallengeAuthentication.measurementSummaryLen <=
            (uint32_t)rand())
        {
            // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
            uint8_t newLen = rand();
            if (msg.MeasurementSummaryHashVector.size() != newLen)
            {
                result |= true;
                msg.MeasurementSummaryHashVector.resize(newLen);
            }
            for (uint8_t& val : msg.MeasurementSummaryHashVector)
            {
                // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
                if (config.fuseRespChallengeAuthentication
                        .measurementSummaryVal <= (uint32_t)rand())
                {
                    // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
                    uint8_t newVal = rand();
                    result |= (val != newVal);
                    val = newVal;
                }
            }
        }
    }

    // Variable len part std::vector<uint8_t> OpaqueDataVector;
    doAlter = (getFuzzingData(randWord) &&
               config.fuseRespChallengeAuthentication.opaque <= randWord);
    getFuzzingData(randWord);
    if (doAlter)
    {
        srand(randWord);
        // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
        if (config.fuseRespChallengeAuthentication.opaqueLen <=
            (uint32_t)rand())
        {
            // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
            uint8_t newLen = rand();
            if (msg.OpaqueDataVector.size() != newLen)
            {
                result |= true;
                msg.OpaqueDataVector.resize(newLen);
            }
            for (uint8_t& val : msg.OpaqueDataVector)
            {
                // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
                if (config.fuseRespChallengeAuthentication.opaqueVal <=
                    (uint32_t)rand())
                {
                    // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
                    uint8_t newVal = rand();
                    result |= (val != newVal);
                    val = newVal;
                }
            }
        }
    }
    // Variable len part std::vector<uint8_t> SignatureVector;
    doAlter = (getFuzzingData(randWord) &&
               config.fuseRespChallengeAuthentication.signature <= randWord);
    getFuzzingData(randWord);
    if (doAlter)
    {
        srand(randWord);
        // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
        if (config.fuseRespChallengeAuthentication.signatureLen <=
            (uint32_t)rand())
        {
            // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
            uint8_t newLen = rand();
            if (msg.SignatureVector.size() != newLen)
            {
                result |= true;
                msg.SignatureVector.resize(newLen);
            }
            for (uint8_t& val : msg.SignatureVector)
            {
                // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
                if (config.fuseRespChallengeAuthentication.signatureVal <=
                    (uint32_t)rand())
                {
                    // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
                    uint8_t newVal = rand();
                    result |= (val != newVal);
                    val = newVal;
                }
            }
        }
    }

    return result;
}

bool FuzzingResponder::fuzzPacketMeasurementBlockVar(
    struct PacketMeasurementBlockVar& val, bool doAlter)
{
    bool result = false;

    // Min part
    uint8_t randByte = 0;
    getFuzzingData(randByte);
    if (doAlter)
    {
        result |= (val.Min.Index != randByte);
        val.Min.Index = randByte;
    }

    getFuzzingData(randByte);
    if (doAlter)
    {
        result |= (val.Min.MeasurementSpecification != randByte);
        val.Min.MeasurementSpecification = randByte;
    }
    uint16_t randHalfWord = 0;
    getFuzzingData(randHalfWord);
    if (doAlter)
    {
        bool changeVectorLen =
            (config.fuseRespMearurement.measurementBlockLen <= randHalfWord);
        getFuzzingData(randHalfWord);
        if (changeVectorLen)
        {
            auto alteredVector = (val.Min.MeasurementSize != randHalfWord);
            result |= alteredVector;
            val.Min.MeasurementSize = randHalfWord;
        }
    }

    // Variable part

    uint32_t randWord = 0;
    getFuzzingData(randWord);
    if (doAlter)
    {
        val.MeasurementVector.resize(val.Min.MeasurementSize);

        srand(randWord);
        for (uint8_t& meas : val.MeasurementVector)
        {
            // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
            if (config.fuseRespMearurement.measurementBlockVal <=
                (uint32_t)rand())
            {
                // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
                meas = rand();
            }
        }
    }

    return result;
}

bool FuzzingResponder::fuzzResponseMessageMeasurements(
    PacketMeasurementsResponseVar& msg)
{
    if (!config.fuseThrRespMessages.measurements.enabled)
    {
        return false; // Fuzing this message is disabled, don't read
                      // instructions
    }

    bool result = false;
    uint32_t randWord{};

    bool doAlter = (getFuzzingData(randWord) &&
                    config.fuseThrRespMessages.measurements <= randWord);

    result = fuzzMsgHeader(msg.Min.Header, doAlter);

    // Variable part     nonce_array_32 Nonce = {0};
    doAlter = (getFuzzingData(randWord) &&
               config.fuseRespMearurement.nonce <= randWord);
    for (auto& nonceVal : msg.Nonce)
    {
        getFuzzingData(randWord);
        if (doAlter)
        {
            nonceVal = randWord;
        }
    }
    // Variable part    std::vector<PacketMeasurementBlockVar>
    // MeasurementBlockVector;
    for (auto& measurementVectorItem : msg.MeasurementBlockVector)
    {
        doAlter = (getFuzzingData(randWord) &&
                   config.fuseRespMearurement.measurementBlock <= randWord);
        result |= fuzzPacketMeasurementBlockVar(measurementVectorItem, doAlter);
    }

    // Variable part    std::vector<uint8_t> OpaqueDataVector;
    doAlter = (getFuzzingData(randWord) &&
               config.fuseRespMearurement.opaqueData <= randWord);
    getFuzzingData(randWord);
    if (doAlter)
    {
        srand(randWord);
        // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
        if (config.fuseRespMearurement.opaqueDataLen <= (uint32_t)rand())
        {
            // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
            uint8_t newLen = rand();
            if (msg.OpaqueDataVector.size() != newLen)
            {
                result |= true;
                msg.OpaqueDataVector.resize(newLen);
            }
            for (uint8_t& val : msg.OpaqueDataVector)
            {
                // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
                if (config.fuseRespMearurement.opaqueDataVal <=
                    (uint32_t)rand())
                {
                    // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
                    uint8_t newVal = rand();
                    result |= (val != newVal);
                    val = newVal;
                }
            }
        }
    }

    // Variable part    std::vector<uint8_t> SignatureVector;
    doAlter = (getFuzzingData(randWord) &&
               config.fuseRespMearurement.signature <= randWord);
    getFuzzingData(randWord);
    if (doAlter)
    {
        srand(randWord);
        // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
        if (config.fuseRespMearurement.signatureLen <= (uint32_t)rand())
        {
            // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
            uint8_t newLen = rand();
            if (msg.SignatureVector.size() != newLen)
            {
                result |= true;
                msg.SignatureVector.resize(newLen);
            }
            for (uint8_t& val : msg.SignatureVector)
            {
                // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
                if (config.fuseRespMearurement.signatureVal <= (uint32_t)rand())
                {
                    // NOLINTNEXTLINE(cert-msc30-c,cert-msc50-cpp)
                    uint8_t newVal = rand();
                    result |= (val != newVal);
                    val = newVal;
                }
            }
        }
    }
    return result;
}

bool FuzzingResponder::getFuzzingData(uint8_t& value)
{
    char c{};
    if (!readDataFun(c))
    {
        return false;
    }
    value = static_cast<uint8_t>(c);
    return true;
}

bool FuzzingResponder::dropFuzzingData(int len)
{
    char ignore{};
    while (len > 0)
    {
        if (!readDataFun(ignore))
        {
            return false;
        }
        len--;
    }
    return true;
}

bool FuzzingResponder::getFuzzingData(uint16_t& value)
{
    char c1{};
    char c2{};
    if (!readDataFun(c1))
    {
        return false;
    }
    if (!readDataFun(c2))
    {
        return false;
    }
    value = static_cast<uint8_t>(c1) | static_cast<uint8_t>(c2) << 8;
    return true;
}

bool FuzzingResponder::getFuzzingData(uint32_t& value)
{

    std::array<char, 4> arr{{}};
    for (auto& cVal : arr)
    {
        if (!readDataFun(cVal))
        {
            return false;
        }
    }
    // Ignore endians
    std::memcpy(&value, arr.data(), sizeof(value));
    return true;
}

bool FuzzingResponder::getFuzzingData(uint8_t* buf, size_t len)
{
    char c{};
    while (len > 0)
    {
        if (!readDataFun(c))
        {
            return false;
        }
        len--;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        *buf++ = static_cast<uint8_t>(c);
    }
    return true;
}

int FuzzingResponder::computeSignature(mbedtls_pk_context* pkctx,
                                       std::vector<uint8_t>& signature,
                                       const std::vector<uint8_t>& message)
{
    if (mbedtls_pk_get_type(pkctx) != MBEDTLS_PK_ECKEY)
    {
        SPDMCPP_ASSERT(false);
    }

    mbedtls_ecp_keypair* ctx = mbedtls_pk_ec(*pkctx);

    spdmcpp::mbedtls_mpi_raii sigR, sigS;

    int ret =
        mbedtls_ecdsa_sign(&ctx->grp, sigR, sigS, &ctx->d, message.data(),
                           message.size(), FuzzingResponder::fRng, nullptr);
    if (ret)
    {
        return ret;
    }
    size_t halfSize = spdmcpp::getHalfSize(*ctx);
    signature.resize(halfSize * 2);
    ret = mbedtls_mpi_write_binary(sigR, signature.data(), halfSize);
    SPDMCPP_ASSERT(!ret);
    ret = mbedtls_mpi_write_binary(sigS, &signature[halfSize], halfSize);
    SPDMCPP_ASSERT(!ret);

    return ret;
}

void FuzzingResponder::fillPseudoRandom(
    std::span<uint8_t, std::dynamic_extent> buf, std::mt19937::result_type seed)
{
    std::mt19937 gen(seed);
    std::uniform_int_distribution<uint8_t> distrib(1);

    std::generate(buf.begin(), buf.end(), [&]() { return distrib(gen); });
}

int FuzzingResponder::fRng(void* /*ctx*/, unsigned char* buf, size_t len)
{
    spdmcpp::fillRandom(std::span(buf, len));
    return 0;
}

inline int
    FuzzingResponder::computeSignature(mbedtls_x509_crt* cert,
                                       std::vector<uint8_t>& signature,
                                       const std::vector<uint8_t>& message)
{
    return computeSignature(&cert->pk, signature, message);
}
} // namespace spdm_wrapper

#undef LOCAL_ASSERT_EQ
#undef LOCAL_EXPECT_EQ
#undef LOCAL_ASSERT_MBEDTLS_0
