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

#include "test_helpers.hpp"

#include <spdmcpp/assert.hpp>
#include <spdmcpp/common.hpp>
#include <spdmcpp/helpers.hpp>
#include <spdmcpp/packet.hpp>

#include <array>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

/*
 * Pragma pack is temporary disabled due to bug in LLVM
 * https://www.mail-archive.com/llvm-bugs@lists.llvm.org/msg69115.html
 */
#ifndef __clang__

using namespace spdmcpp;

/** Mirrors layout in buildSpdm12SignatureContext() — first 100 bytes + hash. */
static void expectBuildSpdm12SignatureContextLayout(
    const std::vector<uint8_t>& result, const char* context, bool is_requester,
    const std::vector<uint8_t>& hash)
{
    const size_t prefix_len = std::strlen(SPDM_VERSION_1_2_SIGNING_PREFIX);
    const size_t spdm_prefix_total =
        prefix_len * SPDM_SIGNING_CONTEXT_PREFIX_REPEAT_COUNT;
    const char* role_prefix =
        is_requester ? SPDM_REQUESTER_PREFIX : SPDM_RESPONDER_PREFIX;
    const size_t role_prefix_len = std::strlen(role_prefix);
    const size_t context_len = std::strlen(context);
    const size_t spdm_context_len = role_prefix_len + context_len;
    const size_t zero_pad_size =
        SPDM_COMBINED_PREFIX_SIZE - spdm_prefix_total - 1 - spdm_context_len;

    ASSERT_EQ(result.size(), SPDM_COMBINED_PREFIX_SIZE + hash.size());
    ASSERT_EQ(spdm_prefix_total + 1 + zero_pad_size + spdm_context_len,
              SPDM_COMBINED_PREFIX_SIZE);

    for (size_t r = 0; r < SPDM_SIGNING_CONTEXT_PREFIX_REPEAT_COUNT; ++r)
    {
        const size_t off = r * prefix_len;
        ASSERT_EQ(std::memcmp(result.data() + off,
                              SPDM_VERSION_1_2_SIGNING_PREFIX, prefix_len),
                  0)
            << "SPDM signing prefix repeat " << r;
    }

    ASSERT_EQ(result[spdm_prefix_total], 0x00);

    for (size_t i = 0; i < zero_pad_size; ++i)
    {
        ASSERT_EQ(result[spdm_prefix_total + 1 + i], 0x00) << "zero pad " << i;
    }

    const size_t role_off = spdm_prefix_total + 1 + zero_pad_size;
    ASSERT_EQ(
        std::memcmp(result.data() + role_off, role_prefix, role_prefix_len), 0);
    ASSERT_EQ(std::memcmp(result.data() + role_off + role_prefix_len, context,
                          context_len),
              0);

    if (!hash.empty())
    {
        ASSERT_EQ(std::memcmp(result.data() + SPDM_COMBINED_PREFIX_SIZE,
                              hash.data(), hash.size()),
                  0);
    }
}

// clang-format off

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SPDMCPP_TEST_ASSERT_RS(rs, val)                                        \
    do                                                                         \
    {                                                                          \
        if ((rs) != (val))                                                     \
        {                                                                      \
            std::cerr << "Unexpected: " #rs " = " << get_cstr(rs)              \
                      << std::endl;                                            \
            std::cerr << " in: "                                               \
                      << __func__ /*NOLINT cppcoreguidelines-pro-bounds-array-to-pointer-decay*/ \
                      << "() @ " << __FILE__ << " : " << std::dec << __LINE__  \
                      << std::endl;                                            \
            return false;                                                      \
        }                                                                      \
    } while (false)

// clang-format on

void print(const std::vector<uint8_t>& buf)
{
    std::ios_base::fmtflags f(std::cerr.flags());
    for (size_t i = 0; i < buf.size(); ++i)
    {
        if (i)
        {
            std::cerr << " 0x";
        }
        else
        {
            std::cerr << "0x";
        }
        std::cerr << std::hex << (int)buf[i];
    }
    std::cerr.flags(f);
}

template <typename T>
inline void
    fillPseudoRandomPacket(T& p,
                           std::mt19937::result_type seed = mt19937DefaultSeed)
{
    SPDMCPP_STATIC_ASSERT(T::sizeIsConstant);
    fillPseudoRandomType(p, seed);
    // NOLINTNEXTLINE cppcoreguidelines-pro-type-reinterpret-cast
    packetMessageHeaderSetRequestresponsecode(reinterpret_cast<uint8_t*>(&p),
                                              T::requestResponseCode);
}

template <typename T>
inline T returnPseudorandomPacket(
    std::mt19937::result_type seed = mt19937DefaultSeed)
{
    T p;
    fillPseudoRandom_packet(p, seed);
    return p;
}

template <class T>
bool packetPseudorandomDecodeEncodeBasic()
{
    SPDMCPP_STATIC_ASSERT(T::sizeIsConstant);
    LogClass log(std::cerr);
    std::vector<uint8_t> src, dst;
    src.resize(sizeof(T));
    fillPseudoRandom(src);
    std::cerr << "src: ";
    print(src);
    std::cerr << std::endl;

    T packet;
    {
        size_t off = 0;
        auto rs = packetDecodeBasic(log, packet, src, off);
        SPDMCPP_TEST_ASSERT_RS(rs, RetStat::OK);
        if (off != src.size())
        {
            std::cerr << "off: " << off << std::endl;
            return false;
        }
    }
    {
        auto rs = packetEncode(packet, dst);
        SPDMCPP_TEST_ASSERT_RS(rs, RetStat::OK);
    }
    std::cerr << "dst: ";
    print(dst);
    std::cerr << std::endl;
    if (!std::equal(src.begin(), src.end(), dst.begin()))
    {
        std::cerr << "src != dst";
        return false;
    }
    return true;
}

template <class T>
bool packetPseudorandomDecodeEncode()
{
    LogClass log(std::cerr);
    SPDMCPP_STATIC_ASSERT(T::sizeIsConstant);
    std::vector<uint8_t> src, dst;
    src.resize(sizeof(T));
    fillPseudoRandom(src);

    packetMessageHeaderSetRequestresponsecode(src.data(),
                                              T::requestResponseCode);

    std::cerr << "src: ";
    print(src);
    std::cerr << std::endl;

    T packet;
    {
        size_t off = 0;
        auto rs = packetDecode(log, packet, src, off);
        SPDMCPP_TEST_ASSERT_RS(rs, RetStat::OK);
        SPDMCPP_ASSERT(off == src.size());
    }
    packet.printMl(log);
    {
        auto rs = packetEncode(packet, dst);
        SPDMCPP_TEST_ASSERT_RS(rs, RetStat::OK);
    }
    std::cerr << "dst: ";
    print(dst);
    std::cerr << std::endl;
    if (!std::equal(src.begin(), src.end(), dst.begin()))
    {
        std::cerr << "src != dst";
        return false;
    }

    src.push_back(0xBA);
    {
        size_t off = 0;
        auto rs = packetDecode(log, packet, src, off);
        SPDMCPP_TEST_ASSERT_RS(rs, RetStat::WARNING_BUFFER_TOO_BIG);
    }
    src.pop_back();
    src.pop_back();
    {
        size_t off = 0;
        auto rs = packetDecode(log, packet, src, off);
        SPDMCPP_TEST_ASSERT_RS(rs, RetStat::ERROR_BUFFER_TOO_SMALL);
    }
    return true;
}

template <class T, typename... Targs>
bool packetEncodeDecode(const T& src, Targs... fargs)
{
    LogClass log(std::cerr);
    log.iprintln("src:");
    src.printMl(log);

    std::vector<uint8_t> buf;
    {
        auto rs = packetEncode(src, buf);
        if (rs != RetStat::OK)
        {
            std::cerr << "RetStat: " << get_cstr(rs) << std::endl;
            return false;
        }
    }
    print(buf);
    std::cerr << std::endl;
    T dst;
    {
        size_t off = 0;
        auto rs = packetDecode(log, dst, buf, off, fargs...);
        if (rs != RetStat::OK)
        {
            std::cerr << "RetStat: " << get_cstr(rs) << std::endl;
            return false;
        }
        if (off != buf.size())
        {
            std::cerr << "invalid final offset: " << off
                      << " compared to buf.size(): " << buf.size() << std::endl;
            return false;
        }
    }
    log.iprintln("dst:");
    dst.printMl(log);
    std::cerr << std::endl;
    return src == dst;
}

template <class T, typename... Targs>
bool packetEncodeDecodeInternal(const T& src, Targs... fargs)
{
    LogClass log(std::cerr);
    log.iprintln("src:");
    src.printMl(log);

    std::vector<uint8_t> buf;
    {
        size_t off = 0;
        auto rs = packetEncodeInternal(src, buf, off);
        if (rs != RetStat::OK)
        {
            std::cerr << "RetStat: " << get_cstr(rs) << std::endl;
            return false;
        }
    }
    print(buf);
    std::cerr << std::endl;
    T dst;
    {
        size_t off = 0;
        auto rs = packetDecodeInternal(log, dst, buf, off, fargs...);
        if (rs != RetStat::OK)
        {
            std::cerr << "RetStat: " << get_cstr(rs) << std::endl;
            return false;
        }
        if (off != buf.size())
        {
            std::cerr << "invalid final offset: " << off
                      << " compared to buf.size(): " << buf.size() << std::endl;
            return false;
        }
    }
    log.iprintln("dst:");
    dst.printMl(log);
    std::cerr << std::endl;
    return src == dst;
}

TEST(packet_pseudorandom_decode_encode, static_size)
{
    EXPECT_TRUE(packetPseudorandomDecodeEncodeBasic<PacketMessageHeader>());
    EXPECT_TRUE(packetPseudorandomDecodeEncodeBasic<PacketVersionNumber>());
    EXPECT_TRUE(packetPseudorandomDecodeEncodeBasic<PacketErrorResponseMin>());
    EXPECT_TRUE(packetPseudorandomDecodeEncodeBasic<PacketCertificateChain>());
    EXPECT_TRUE(
        packetPseudorandomDecodeEncodeBasic<PacketMeasurementBlockMin>());

    EXPECT_TRUE(packetPseudorandomDecodeEncode<PacketVersionResponseMin>());
    EXPECT_TRUE(
        packetPseudorandomDecodeEncode<PacketNegotiateAlgorithmsRequestMin>());
    EXPECT_TRUE(packetPseudorandomDecodeEncode<PacketAlgorithmsResponseMin>());
    EXPECT_TRUE(packetPseudorandomDecodeEncode<PacketGetDigestsRequest>());
    EXPECT_TRUE(packetPseudorandomDecodeEncode<PacketDigestsResponseMin>());
    EXPECT_TRUE(packetPseudorandomDecodeEncode<PacketGetCertificateRequest>());
    EXPECT_TRUE(packetPseudorandomDecodeEncode<PacketCertificateResponseMin>());

    EXPECT_TRUE(
        packetPseudorandomDecodeEncode<PacketGetMeasurementsRequestMin>());
    EXPECT_TRUE(
        packetPseudorandomDecodeEncode<PacketMeasurementsResponseMin>());
}

TEST(packet_pseudorandom_encode_decode, PacketErrorResponseVar)
{
    PacketErrorResponseVar p;
    fillPseudoRandomPacket(p.Min);
    //     p.VersionNumberEntries.push_back(
    //         returnPseudoRandomType<packet_version_number>());
    //     p.VersionNumberEntries.push_back(
    //         returnPseudoRandomType<packet_version_number>());
    EXPECT_TRUE(packetEncodeDecode(p));
}

TEST(packet_pseudorandom_encode_decode, PacketVersionResponseVar)
{
    PacketVersionResponseVar p;
    fillPseudoRandomPacket(p.Min);
    p.VersionNumberEntries.push_back(
        returnPseudoRandomType<PacketVersionNumber>());
    p.VersionNumberEntries.push_back(
        returnPseudoRandomType<PacketVersionNumber>());
    EXPECT_TRUE(packetEncodeDecode(p));
}

TEST(packet_pseudorandom_encode_decode, PacketNegotiateAlgorithmsRequestVar)
{
    PacketNegotiateAlgorithmsRequestVar p;
    fillPseudoRandomPacket(p.Min);

    p.PacketReqAlgVector.push_back(
        PacketReqAlgStruct::buildAlgSupported(AlgTypeEnum::DHE, 0x1b, 0x00));
    p.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildAlgSupported(
        AlgTypeEnum::AEADCipherSuite, 0x06, 0x00));
    p.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildAlgSupported(
        AlgTypeEnum::ReqBaseAsymAlg, 0x0F, 0x00));
    p.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildAlgSupported(
        AlgTypeEnum::KeySchedule, 0x01, 0x00));

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packetEncodeDecode(p));
}

/** Malicious AlgCount: FixedAlgCount=15 exceeds AlgSupported (14). */
TEST(packet_req_alg_struct_decode, reject_fixed_alg_count_exceeding_storage)
{
    LogClass log(std::cerr);
    PacketReqAlgStruct decoded{};
    std::vector<uint8_t> buf;
    buf.push_back(static_cast<uint8_t>(AlgTypeEnum::DHE));
    buf.push_back(0xF0u); // FixedAlgCount=15, ExtAlgCount=0

    size_t off = 0;
    EXPECT_EQ(packetDecodeInternal(log, decoded, buf, off),
              RetStat::ERROR_INVALID_PARAMETER);
}

/** AlgCount 0/0: only type + count bytes. */
TEST(packet_req_alg_struct_decode, zero_fixed_and_zero_ext_minimal_wire)
{
    LogClass log(std::cerr);
    PacketReqAlgStruct decoded{};
    std::vector<uint8_t> buf;
    buf.push_back(static_cast<uint8_t>(AlgTypeEnum::DHE));
    buf.push_back(0x00u);

    size_t off = 0;
    ASSERT_EQ(packetDecodeInternal(log, decoded, buf, off), RetStat::OK);
    EXPECT_EQ(off, buf.size());
    EXPECT_EQ(decoded.getFixedAlgCount(), 0u);
    EXPECT_EQ(decoded.getExtAlgCount(), 0u);
}

/** Max supported FixedAlgCount (14) with ExtAlgCount 0. */
TEST(packet_req_alg_struct_decode, max_fixed_alg_count_decodes)
{
    LogClass log(std::cerr);
    PacketReqAlgStruct decoded{};
    std::vector<uint8_t> buf;
    buf.push_back(static_cast<uint8_t>(AlgTypeEnum::DHE));
    buf.push_back(0xE0u); // FixedAlgCount=14, ExtAlgCount=0
    buf.resize(buf.size() + 14, 0xABu);

    size_t off = 0;
    ASSERT_EQ(packetDecodeInternal(log, decoded, buf, off), RetStat::OK);
    EXPECT_EQ(off, buf.size());
    EXPECT_EQ(decoded.getFixedAlgCount(), 14u);
    EXPECT_EQ(decoded.getExtAlgCount(), 0u);
    for (size_t i = 0; i < 14; ++i)
    {
        EXPECT_EQ(decoded.AlgSupported[i], 0xABu);
    }
}

/** Max ExtAlgCount (15) from nibble with FixedAlgCount 0 (boundary for ext
 * guard). */
TEST(packet_req_alg_struct_decode, max_ext_alg_count_decodes)
{
    LogClass log(std::cerr);
    PacketReqAlgStruct decoded{};
    std::vector<uint8_t> buf;
    buf.push_back(static_cast<uint8_t>(AlgTypeEnum::DHE));
    buf.push_back(0x0Fu); // FixedAlgCount=0, ExtAlgCount=15
    const size_t extBytes = 15 * sizeof(uint32_t);
    buf.resize(buf.size() + extBytes, 0u);

    size_t off = 0;
    ASSERT_EQ(packetDecodeInternal(log, decoded, buf, off), RetStat::OK);
    EXPECT_EQ(off, buf.size());
    EXPECT_EQ(decoded.getFixedAlgCount(), 0u);
    EXPECT_EQ(decoded.getExtAlgCount(), 15u);
    for (size_t i = 0; i < 15; ++i)
    {
        EXPECT_EQ(decoded.AlgExternal[i], 0u);
    }
}

/** After bounds pass, short buffer still fails without OOB read. */
TEST(packet_req_alg_struct_decode, short_buffer_after_valid_counts)
{
    LogClass log(std::cerr);
    PacketReqAlgStruct decoded{};
    std::vector<uint8_t> buf;
    buf.push_back(static_cast<uint8_t>(AlgTypeEnum::DHE));
    buf.push_back(0xE0u); // 14 fixed bytes expected, provide only 10
    buf.resize(buf.size() + 10, 0u);

    size_t off = 0;
    EXPECT_EQ(packetDecodeInternal(log, decoded, buf, off),
              RetStat::ERROR_BUFFER_TOO_SMALL);
}

TEST(packet_pseudorandom_encode_decode, PacketAlgorithmsResponseVar)
{
    PacketAlgorithmsResponseVar p;
    fillPseudoRandomPacket(p.Min);

    p.PacketReqAlgVector.push_back(
        PacketReqAlgStruct::buildAlgSupported(AlgTypeEnum::DHE, 0x1b, 0x00));
    p.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildAlgSupported(
        AlgTypeEnum::AEADCipherSuite, 0x06, 0x00));
    p.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildAlgSupported(
        AlgTypeEnum::ReqBaseAsymAlg, 0x0F, 0x00));
    p.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildAlgSupported(
        AlgTypeEnum::KeySchedule, 0x01, 0x00));

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packetEncodeDecode(p));
}

TEST(packet_pseudorandom_encode_decode, PacketDigestsResponseVar)
{
    PacketDecodeInfo info;
    info.BaseHashSize = 32;

    PacketDigestsResponseVar p;

    fillPseudoRandomPacket(p.Min);

    p.Digests[0].resize(info.BaseHashSize);
    fillPseudoRandom(p.Digests[0]);

    p.Digests[1].resize(info.BaseHashSize);
    fillPseudoRandom(p.Digests[1]);

    p.Digests[7].resize(info.BaseHashSize);
    fillPseudoRandom(p.Digests[7]);

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packetEncodeDecode(p, info));
}

TEST(packet_pseudorandom_encode_decode, PacketCertificateResponseVar)
{
    PacketCertificateResponseVar p;

    fillPseudoRandomPacket(p.Min);

    p.CertificateVector.resize(1023);
    fillPseudoRandom(p.CertificateVector);

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packetEncodeDecode(p));
}

/** Regression: PortionLength must not permit reading past buf end. */
TEST(packet_certificate_response_var_decode,
     truncated_payload_returns_buffer_too_small)
{
    LogClass log(std::cerr);
    PacketCertificateResponseVar p;

    p.Min.Header.MessageVersion = MessageVersionEnum::SPDM_1_2;
    p.Min.Header.requestResponseCode =
        RequestResponseEnum::RESPONSE_CERTIFICATE;
    p.CertificateVector.resize(10);
    fillPseudoRandom(p.CertificateVector);

    ASSERT_EQ(p.finalize(), RetStat::OK);

    std::vector<uint8_t> buf;
    ASSERT_EQ(packetEncode(p, buf), RetStat::OK);

    ASSERT_GT(buf.size(), 5u);
    buf.resize(buf.size() - 5);

    PacketCertificateResponseVar decoded;
    size_t off = 0;
    EXPECT_EQ(packetDecode(log, decoded, buf, off),
              RetStat::ERROR_BUFFER_TOO_SMALL);
}

/** Off-by-one: header still claims full PortionLength but one payload byte is
 * missing. */
TEST(packet_certificate_response_var_decode,
     truncated_payload_off_by_one_returns_buffer_too_small)
{
    LogClass log(std::cerr);
    PacketCertificateResponseVar p;

    p.Min.Header.MessageVersion = MessageVersionEnum::SPDM_1_2;
    p.Min.Header.requestResponseCode =
        RequestResponseEnum::RESPONSE_CERTIFICATE;
    p.CertificateVector.resize(10);
    fillPseudoRandom(p.CertificateVector);

    ASSERT_EQ(p.finalize(), RetStat::OK);

    std::vector<uint8_t> buf;
    ASSERT_EQ(packetEncode(p, buf), RetStat::OK);

    ASSERT_GT(buf.size(), 1u);
    buf.resize(buf.size() - 1);

    PacketCertificateResponseVar decoded;
    size_t off = 0;
    EXPECT_EQ(packetDecode(log, decoded, buf, off),
              RetStat::ERROR_BUFFER_TOO_SMALL);
}

/** Decode succeeds when payload length matches header (boundary sanity). */
TEST(packet_certificate_response_var_decode, exact_fit_payload_decodes)
{
    LogClass log(std::cerr);
    PacketCertificateResponseVar p;

    p.Min.Header.MessageVersion = MessageVersionEnum::SPDM_1_2;
    p.Min.Header.requestResponseCode =
        RequestResponseEnum::RESPONSE_CERTIFICATE;
    p.CertificateVector.resize(10);
    fillPseudoRandom(p.CertificateVector);

    ASSERT_EQ(p.finalize(), RetStat::OK);

    std::vector<uint8_t> buf;
    ASSERT_EQ(packetEncode(p, buf), RetStat::OK);

    PacketCertificateResponseVar decoded;
    size_t off = 0;
    ASSERT_EQ(packetDecode(log, decoded, buf, off), RetStat::OK);
    EXPECT_EQ(off, buf.size());
    EXPECT_EQ(decoded.CertificateVector.size(), 10U);
}

TEST(packet_certificate_response_var_decode,
     zero_length_certificate_vector_decodes)
{
    LogClass log(std::cerr);
    PacketCertificateResponseVar p;

    p.Min.Header.MessageVersion = MessageVersionEnum::SPDM_1_2;
    p.Min.Header.requestResponseCode =
        RequestResponseEnum::RESPONSE_CERTIFICATE;
    p.CertificateVector.resize(0);

    ASSERT_EQ(p.finalize(), RetStat::OK);

    std::vector<uint8_t> buf;
    ASSERT_EQ(packetEncode(p, buf), RetStat::OK);

    PacketCertificateResponseVar decoded;
    size_t off = 0;
    ASSERT_EQ(packetDecode(log, decoded, buf, off), RetStat::OK);
    EXPECT_EQ(off, buf.size());
    EXPECT_EQ(decoded.CertificateVector.size(), 0U);
}

TEST(packet_pseudorandom_encode_decode, PacketGetMeasurementsRequestVar)
{
    PacketGetMeasurementsRequestVar p;

    fillPseudoRandomPacket(p.Min);

    p.Min.Header.Param1 = 0; // need to clear to test lack of Nonce
    // fillPseudoRandom(p.Nonce);
    // p.SlotIDParam = 1;

    //     EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packetEncodeDecode(p));
}

TEST(packet_pseudorandom_encode_decode, PacketGetMeasurementsRequestVar_1)
{
    PacketGetMeasurementsRequestVar p;

    fillPseudoRandomPacket(p.Min);

    p.setNonce();
    fillPseudoRandom(p.Nonce);
    p.SlotIDParam = 1;

    //     EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packetEncodeDecode(p));
}

TEST(packet_pseudorandom_encode_decode, PacketMeasurementBlockVar)
{
    PacketMeasurementBlockVar p;

    fillPseudoRandomType(p.Min);

    p.MeasurementVector.resize(1023);
    fillPseudoRandom(p.MeasurementVector);

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packetEncodeDecodeInternal(p));
}

TEST(packet_pseudorandom_encode_decode, PacketMeasurementFieldVar)
{
    PacketMeasurementFieldVar p;

    fillPseudoRandomType(p.Min);

    p.ValueVector.resize(1023);
    fillPseudoRandom(p.ValueVector);

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packetEncodeDecodeInternal(p));
}

TEST(packet_pseudorandom_encode_decode, PacketMeasurementsResponseVar)
{
    PacketDecodeInfo info;
    info.GetMeasurementsParam1 = 0;
    info.BaseHashSize = 32;
    info.SignatureSize = 48;

    PacketMeasurementsResponseVar p;

    fillPseudoRandomPacket(p.Min);

    p.OpaqueDataVector.resize(127);
    fillPseudoRandom(p.OpaqueDataVector);

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packetEncodeDecode(p, info));
}

TEST(packet_pseudorandom_encode_decode, PacketMeasurementsResponseVar_1)
{
    PacketDecodeInfo info;
    info.GetMeasurementsParam1 = 1;
    info.BaseHashSize = 32;
    info.SignatureSize = 48;

    PacketMeasurementsResponseVar p;

    fillPseudoRandomPacket(p.Min);

    p.MeasurementBlockVector.resize(3);
    {
        PacketMeasurementBlockVar& b = p.MeasurementBlockVector[0];
        fillPseudoRandomType(b.Min);
        b.MeasurementVector.resize(1023);
        fillPseudoRandom(b.MeasurementVector);
        EXPECT_EQ(b.finalize(), RetStat::OK);
    }
    {
        PacketMeasurementBlockVar& b = p.MeasurementBlockVector[1];
        fillPseudoRandomType(b.Min);
        b.MeasurementVector.resize(3);
        fillPseudoRandom(b.MeasurementVector);
        EXPECT_EQ(b.finalize(), RetStat::OK);
    }
    {
        PacketMeasurementBlockVar& b = p.MeasurementBlockVector[2];
        fillPseudoRandomType(b.Min);
        b.MeasurementVector.resize(107);
        fillPseudoRandom(b.MeasurementVector);
        EXPECT_EQ(b.finalize(), RetStat::OK);
    }

    p.SignatureVector.resize(info.SignatureSize);
    fillPseudoRandom(p.SignatureVector);

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packetEncodeDecode(p, info));
}

TEST(packet_spdm12_encode_decode, PacketGetCapabilitiesRequest_SPDM12)
{
    LogClass log(std::cerr);
    PacketGetCapabilitiesRequest p;
    p.Header.MessageVersion = MessageVersionEnum::SPDM_1_2;
    p.CTExponent = 5;
    p.Flags = RequesterCapabilitiesFlags::CERT_CAP;
    p.DataTransferSize = 1024;
    p.MaxSPDMmsgSize = 4096;

    std::vector<uint8_t> buf;
    size_t off = 0;
    EXPECT_EQ(packetEncodeInternal(p, buf, off), RetStat::OK);

    PacketGetCapabilitiesRequest decoded;
    off = 0;
    EXPECT_EQ(packetDecodeInternal(log, decoded, buf, off), RetStat::OK);
    EXPECT_EQ(decoded.DataTransferSize, 1024);
    EXPECT_EQ(decoded.MaxSPDMmsgSize, 4096);
    EXPECT_EQ(decoded.CTExponent, 5);
}

TEST(packet_spdm12_encode_decode, PacketGetCapabilitiesRequest_SPDM12_MaxValues)
{
    LogClass log(std::cerr);
    PacketGetCapabilitiesRequest p;
    p.Header.MessageVersion = MessageVersionEnum::SPDM_1_2;
    p.CTExponent = 12;
    p.Flags = RequesterCapabilitiesFlags::MEAS_CAP;
    p.DataTransferSize = 0xFFFFFFFF;
    p.MaxSPDMmsgSize = 0xFFFFFFFF;

    std::vector<uint8_t> buf;
    size_t off = 0;
    EXPECT_EQ(packetEncodeInternal(p, buf, off), RetStat::OK);

    PacketGetCapabilitiesRequest decoded;
    off = 0;
    EXPECT_EQ(packetDecodeInternal(log, decoded, buf, off), RetStat::OK);
    EXPECT_EQ(decoded.DataTransferSize, 0xFFFFFFFF);
    EXPECT_EQ(decoded.MaxSPDMmsgSize, 0xFFFFFFFF);
}

TEST(packet_spdm12_encode_decode, PacketGetCapabilitiesRequest_SPDM12_ZeroSizes)
{
    LogClass log(std::cerr);
    PacketGetCapabilitiesRequest p;
    p.Header.MessageVersion = MessageVersionEnum::SPDM_1_2;
    p.CTExponent = 0;
    p.Flags = RequesterCapabilitiesFlags::NIL;
    p.DataTransferSize = 0;
    p.MaxSPDMmsgSize = 0;

    std::vector<uint8_t> buf;
    size_t off = 0;
    EXPECT_EQ(packetEncodeInternal(p, buf, off), RetStat::OK);

    PacketGetCapabilitiesRequest decoded;
    off = 0;
    EXPECT_EQ(packetDecodeInternal(log, decoded, buf, off), RetStat::OK);
    EXPECT_EQ(decoded.DataTransferSize, 0);
    EXPECT_EQ(decoded.MaxSPDMmsgSize, 0);
}

TEST(packet_spdm12_encode_decode, PacketGetCapabilitiesRequest_SPDM11)
{
    LogClass log(std::cerr);
    PacketGetCapabilitiesRequest p;
    p.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;
    p.CTExponent = 3;
    p.Flags = RequesterCapabilitiesFlags::CERT_CAP;
    p.DataTransferSize = 1024;
    p.MaxSPDMmsgSize = 4096;

    std::vector<uint8_t> buf;
    size_t off = 0;
    EXPECT_EQ(packetEncodeInternal(p, buf, off), RetStat::OK);

    PacketGetCapabilitiesRequest decoded;
    off = 0;
    EXPECT_EQ(packetDecodeInternal(log, decoded, buf, off), RetStat::OK);
    EXPECT_EQ(decoded.DataTransferSize, 0);
    EXPECT_EQ(decoded.MaxSPDMmsgSize, 0);
}

TEST(packet_spdm12_encode_decode, PacketCapabilitiesResponse_SPDM12)
{
    LogClass log(std::cerr);
    PacketCapabilitiesResponse p;
    p.Header.MessageVersion = MessageVersionEnum::SPDM_1_2;
    p.CTExponent = 7;
    p.Flags = ResponderCapabilitiesFlags::CERT_CAP;
    p.DataTransferSize = 2048;
    p.MaxSPDMmsgSize = 8192;

    std::vector<uint8_t> buf;
    size_t off = 0;
    EXPECT_EQ(packetEncodeInternal(p, buf, off), RetStat::OK);

    PacketCapabilitiesResponse decoded;
    off = 0;
    EXPECT_EQ(packetDecodeInternal(log, decoded, buf, off), RetStat::OK);
    EXPECT_EQ(decoded.DataTransferSize, 2048);
    EXPECT_EQ(decoded.MaxSPDMmsgSize, 8192);
    EXPECT_EQ(decoded.CTExponent, 7);
}

TEST(packet_spdm12_encode_decode, PacketCapabilitiesResponse_SPDM12_MaxValues)
{
    LogClass log(std::cerr);
    PacketCapabilitiesResponse p;
    p.Header.MessageVersion = MessageVersionEnum::SPDM_1_2;
    p.CTExponent = 15;
    p.Flags = ResponderCapabilitiesFlags::MEAS_CAP;
    p.DataTransferSize = 0xFFFFFFFF;
    p.MaxSPDMmsgSize = 0xFFFFFFFF;

    std::vector<uint8_t> buf;
    size_t off = 0;
    EXPECT_EQ(packetEncodeInternal(p, buf, off), RetStat::OK);

    PacketCapabilitiesResponse decoded;
    off = 0;
    EXPECT_EQ(packetDecodeInternal(log, decoded, buf, off), RetStat::OK);
    EXPECT_EQ(decoded.DataTransferSize, 0xFFFFFFFF);
    EXPECT_EQ(decoded.MaxSPDMmsgSize, 0xFFFFFFFF);
}

TEST(packet_spdm12_encode_decode, PacketCapabilitiesResponse_SPDM12_Typical)
{
    LogClass log(std::cerr);
    PacketCapabilitiesResponse p;
    p.Header.MessageVersion = MessageVersionEnum::SPDM_1_2;
    p.CTExponent = 10;
    p.Flags = ResponderCapabilitiesFlags::CACHE_CAP;
    p.DataTransferSize = 512;
    p.MaxSPDMmsgSize = 2048;

    std::vector<uint8_t> buf;
    size_t off = 0;
    EXPECT_EQ(packetEncodeInternal(p, buf, off), RetStat::OK);

    PacketCapabilitiesResponse decoded;
    off = 0;
    EXPECT_EQ(packetDecodeInternal(log, decoded, buf, off), RetStat::OK);
    EXPECT_EQ(decoded.DataTransferSize, 512);
    EXPECT_EQ(decoded.MaxSPDMmsgSize, 2048);
}

TEST(packet_spdm12_encode_decode, PacketCapabilitiesResponse_SPDM11)
{
    LogClass log(std::cerr);
    PacketCapabilitiesResponse p;
    p.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;
    p.CTExponent = 4;
    p.Flags = ResponderCapabilitiesFlags::CERT_CAP;
    p.DataTransferSize = 2048;
    p.MaxSPDMmsgSize = 8192;

    std::vector<uint8_t> buf;
    size_t off = 0;
    EXPECT_EQ(packetEncodeInternal(p, buf, off), RetStat::OK);

    PacketCapabilitiesResponse decoded;
    off = 0;
    EXPECT_EQ(packetDecodeInternal(log, decoded, buf, off), RetStat::OK);
    EXPECT_EQ(decoded.DataTransferSize, 0);
    EXPECT_EQ(decoded.MaxSPDMmsgSize, 0);
}

TEST(packet_spdm12, GetCapabilitiesRequest_Size_SPDM12)
{
    PacketGetCapabilitiesRequest p12;
    p12.Header.MessageVersion = MessageVersionEnum::SPDM_1_2;

    PacketGetCapabilitiesRequest p11;
    p11.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;

    EXPECT_EQ(p12.getSize(), p11.getSize() + 8);
}

TEST(packet_spdm12, CapabilitiesResponse_Size_SPDM12)
{
    PacketCapabilitiesResponse p12;
    p12.Header.MessageVersion = MessageVersionEnum::SPDM_1_2;

    PacketCapabilitiesResponse p11;
    p11.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;

    EXPECT_EQ(p12.getSize(), p11.getSize() + 8);
}

TEST(packet_spdm12, BuildSpdm12SignatureContext_Requester)
{
    using namespace spdmcpp;
    const char* context = "measurement";
    std::vector<uint8_t> hash = {0x01, 0x02, 0x03, 0x04,
                                 0x05, 0x06, 0x07, 0x08};

    auto result = buildSpdm12SignatureContext(context, true, hash);

    expectBuildSpdm12SignatureContextLayout(result, context, true, hash);
}

TEST(packet_spdm12, BuildSpdm12SignatureContext_Responder)
{
    using namespace spdmcpp;
    const char* context = "challenge_auth";
    std::vector<uint8_t> hash = {0xAA, 0xBB, 0xCC, 0xDD};

    auto result = buildSpdm12SignatureContext(context, false, hash);
    expectBuildSpdm12SignatureContextLayout(result, context, false, hash);
}

TEST(packet_spdm12, BuildSpdm12SignatureContext_EmptyHash)
{
    using namespace spdmcpp;
    const char* context = "key_exchange";
    std::vector<uint8_t> hash;

    auto result = buildSpdm12SignatureContext(context, true, hash);
    expectBuildSpdm12SignatureContextLayout(result, context, true, hash);
}

TEST(packet_spdm12, BuildSpdm12SignatureContext_LargeHash)
{
    using namespace spdmcpp;
    const char* context = "finish";
    std::vector<uint8_t> hash(64, 0xFF); // 64 bytes of 0xFF

    auto result = buildSpdm12SignatureContext(context, false, hash);
    expectBuildSpdm12SignatureContextLayout(result, context, false, hash);
}

TEST(packet_spdm12, BuildSpdm12SignatureContext_DifferentContexts)
{
    using namespace spdmcpp;
    std::vector<uint8_t> hash = {0x11, 0x22, 0x33};

    auto result1 = buildSpdm12SignatureContext("short", true, hash);
    auto result2 = buildSpdm12SignatureContext("longer_context", true, hash);
    auto result3 = buildSpdm12SignatureContext("", true, hash);

    expectBuildSpdm12SignatureContextLayout(result1, "short", true, hash);
    expectBuildSpdm12SignatureContextLayout(result2, "longer_context", true,
                                            hash);
    expectBuildSpdm12SignatureContextLayout(result3, "", true, hash);

    EXPECT_NE(result1, result2);
    EXPECT_NE(result2, result3);
}

TEST(packet_spdm12, BuildSpdm12SignatureContext_RequesterVsResponder)
{
    using namespace spdmcpp;
    const char* context = "same_context";
    std::vector<uint8_t> hash = {0xAA, 0xBB};

    auto requester_result = buildSpdm12SignatureContext(context, true, hash);
    auto responder_result = buildSpdm12SignatureContext(context, false, hash);

    expectBuildSpdm12SignatureContextLayout(requester_result, context, true,
                                            hash);
    expectBuildSpdm12SignatureContextLayout(responder_result, context, false,
                                            hash);
    EXPECT_NE(requester_result, responder_result);
}

TEST(packet_spdm12, BuildSpdm12SignatureContext_ContextMaxLengthFitsPrefixField)
{
    using namespace spdmcpp;
    const size_t max_base_context_len =
        SPDM_COMBINED_PREFIX_SIZE -
        std::strlen(SPDM_VERSION_1_2_SIGNING_PREFIX) *
            SPDM_SIGNING_CONTEXT_PREFIX_REPEAT_COUNT -
        1 - std::strlen(SPDM_REQUESTER_PREFIX);
    ASSERT_EQ(max_base_context_len, 25u);

    const std::string context(max_base_context_len, 'z');
    std::vector<uint8_t> hash = {0x7E, 0x7F};

    auto requester = buildSpdm12SignatureContext(context.c_str(), true, hash);
    auto responder = buildSpdm12SignatureContext(context.c_str(), false, hash);

    expectBuildSpdm12SignatureContextLayout(requester, context.c_str(), true,
                                            hash);
    expectBuildSpdm12SignatureContextLayout(responder, context.c_str(), false,
                                            hash);
}

TEST(packet_spdm12, BuildSpdm12SignatureContext_ContextTooLongForPrefixField)
{
    using namespace spdmcpp;
    const size_t max_base_context_len =
        SPDM_COMBINED_PREFIX_SIZE -
        std::strlen(SPDM_VERSION_1_2_SIGNING_PREFIX) *
            SPDM_SIGNING_CONTEXT_PREFIX_REPEAT_COUNT -
        1 - std::strlen(SPDM_REQUESTER_PREFIX);

    const std::string context(max_base_context_len + 1, 'z');
    std::vector<uint8_t> hash = {0x03, 0x04};

    EXPECT_ANY_THROW(buildSpdm12SignatureContext(context.c_str(), true, hash));
    EXPECT_ANY_THROW(buildSpdm12SignatureContext(context.c_str(), false, hash));
}

TEST(packet_spdm12, BuildSpdm12SignatureContext_HashLongerThanTypicalDigests)
{
    using namespace spdmcpp;
    const char* context = SPDM_MEASUREMENTS_SIGN_CONTEXT;
    std::vector<uint8_t> hash(128);
    for (size_t i = 0; i < hash.size(); ++i)
    {
        hash[i] = static_cast<uint8_t>(i & 0xFF);
    }

    auto result = buildSpdm12SignatureContext(context, false, hash);
    ASSERT_EQ(result.size(), SPDM_COMBINED_PREFIX_SIZE + hash.size());
    expectBuildSpdm12SignatureContextLayout(result, context, false, hash);
}

TEST(packet_version, GetMessageVersion_SPDM10)
{
    PacketVersionNumber ver;
    ver.setMajor(1);
    ver.setMinor(0);

    EXPECT_EQ(ver.getMessageVersion(), MessageVersionEnum::SPDM_1_0);
    EXPECT_EQ(ver.getMajor(), 1);
    EXPECT_EQ(ver.getMinor(), 0);
}

TEST(packet_version, GetMessageVersion_SPDM11)
{
    PacketVersionNumber ver;
    ver.setMajor(1);
    ver.setMinor(1);

    EXPECT_EQ(ver.getMessageVersion(), MessageVersionEnum::SPDM_1_1);
    EXPECT_EQ(ver.getMajor(), 1);
    EXPECT_EQ(ver.getMinor(), 1);
}

TEST(packet_version, GetMessageVersion_SPDM12)
{
    PacketVersionNumber ver;
    ver.setMajor(1);
    ver.setMinor(2);

    EXPECT_EQ(ver.getMessageVersion(), MessageVersionEnum::SPDM_1_2);
    EXPECT_EQ(ver.getMajor(), 1);
    EXPECT_EQ(ver.getMinor(), 2);
}

TEST(packet_version, GetMessageVersion_Unknown)
{
    PacketVersionNumber ver;
    ver.setMajor(2);
    ver.setMinor(0);

    EXPECT_EQ(ver.getMessageVersion(), MessageVersionEnum::UNKNOWN);
}

TEST(packet_version, GetMessageVersion_AllVersions)
{
    {
        PacketVersionNumber ver;
        ver.Bits = (1 << 12) | (0 << 8);
        EXPECT_EQ(ver.getMessageVersion(), MessageVersionEnum::SPDM_1_0);
    }
    {
        PacketVersionNumber ver;
        ver.Bits = (1 << 12) | (1 << 8);
        EXPECT_EQ(ver.getMessageVersion(), MessageVersionEnum::SPDM_1_1);
    }
    {
        PacketVersionNumber ver;
        ver.Bits = (1 << 12) | (2 << 8);
        EXPECT_EQ(ver.getMessageVersion(), MessageVersionEnum::SPDM_1_2);
    }
    {
        PacketVersionNumber ver;
        ver.Bits = (1 << 12) | (3 << 8);
        EXPECT_EQ(ver.getMessageVersion(), MessageVersionEnum::UNKNOWN);
    }
}

TEST(PacketMeasurementsResponseVar_finalize, sets_NumberOfBlocks)
{
    PacketMeasurementsResponseVar p;
    p.MeasurementBlockVector.resize(2);
    for (auto& b : p.MeasurementBlockVector)
    {
        fillPseudoRandomType(b.Min);
        b.MeasurementVector.resize(4);
        fillPseudoRandom(b.MeasurementVector);
        EXPECT_EQ(b.finalize(), RetStat::OK);
    }
    EXPECT_EQ(p.finalize(), RetStat::OK);
    EXPECT_EQ(p.Min.NumberOfBlocks, 2);
}

TEST(PacketMeasurementsResponseVar_finalize, overflow_guard)
{
    PacketMeasurementsResponseVar p;
    // 256 blocks exceeds uint8_t::max — finalize must reject
    p.MeasurementBlockVector.resize(256);
    for (auto& b : p.MeasurementBlockVector)
    {
        b.MeasurementVector.resize(1);
        b.MeasurementVector[0] = 0xAB;
        EXPECT_EQ(b.finalize(), RetStat::OK);
    }
    EXPECT_EQ(p.finalize(), RetStat::ERROR_UNKNOWN);
}

TEST(PacketMeasurementsResponseVar_finalize, max_uint8_boundary)
{
    PacketMeasurementsResponseVar p;
    // 255 blocks == uint8_t::max — finalize must succeed
    p.MeasurementBlockVector.resize(255);
    for (auto& b : p.MeasurementBlockVector)
    {
        b.MeasurementVector.resize(1);
        b.MeasurementVector[0] = 0xAB;
        EXPECT_EQ(b.finalize(), RetStat::OK);
    }
    EXPECT_EQ(p.finalize(), RetStat::OK);
    EXPECT_EQ(p.Min.NumberOfBlocks, 255);
}

TEST(PacketMeasurementsResponseVar_decode, mismatch_NumberOfBlocks)
{
    PacketDecodeInfo info;
    info.GetMeasurementsParam1 = 0;
    info.BaseHashSize = 32;
    info.SignatureSize = 0;

    PacketMeasurementsResponseVar p;
    p.MeasurementBlockVector.resize(2);
    for (auto& b : p.MeasurementBlockVector)
    {
        fillPseudoRandomType(b.Min);
        b.MeasurementVector.resize(4);
        fillPseudoRandom(b.MeasurementVector);
        EXPECT_EQ(b.finalize(), RetStat::OK);
    }
    EXPECT_EQ(p.finalize(), RetStat::OK);

    std::vector<uint8_t> buf;
    EXPECT_EQ(packetEncode(p, buf), RetStat::OK);

    // NumberOfBlocks is at byte offset 4 (after 4-byte PacketMessageHeader).
    // Corrupt it so declared count != actual encoded blocks.
    buf[4] = 99;

    LogClass log(std::cerr);
    PacketMeasurementsResponseVar q;
    size_t off = 0;
    EXPECT_EQ(packetDecode(log, q, buf, off, info), RetStat::ERROR_UNKNOWN);
}

#endif