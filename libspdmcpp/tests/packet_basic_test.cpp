/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
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
#include <spdmcpp/helpers.hpp>
#include <spdmcpp/packet.hpp>

#include <array>
#include <cstring>
#include <random>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

/*
 * Pragma pack is temporary disabled due to bug in LLVM
 * https://www.mail-archive.com/llvm-bugs@lists.llvm.org/msg69115.html
*/
#ifndef __clang__

using namespace spdmcpp;

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
        auto rs = packetDecodeInternal(log,dst, buf, off, fargs...);
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
    EXPECT_TRUE(packetPseudorandomDecodeEncode<PacketGetCapabilitiesRequest>());
    EXPECT_TRUE(packetPseudorandomDecodeEncode<PacketCapabilitiesResponse>());
    EXPECT_TRUE(
        packetPseudorandomDecodeEncode<PacketNegotiateAlgorithmsRequestMin>());
    EXPECT_TRUE(packetPseudorandomDecodeEncode<PacketAlgorithmsResponseMin>());
    EXPECT_TRUE(packetPseudorandomDecodeEncode<PacketGetDigestsRequest>());
    EXPECT_TRUE(packetPseudorandomDecodeEncode<PacketDigestsResponseMin>());
    EXPECT_TRUE(packetPseudorandomDecodeEncode<PacketGetCertificateRequest>());
    EXPECT_TRUE(packetPseudorandomDecodeEncode<PacketCertificateResponseMin>());
    EXPECT_TRUE(packetPseudorandomDecodeEncode<PacketChallengeRequest>());
    EXPECT_TRUE(
        packetPseudorandomDecodeEncode<PacketChallengeAuthResponseMin>());

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

TEST(packet_pseudorandom_encode_decode, PacketChallengeAuthResponseVar)
{
    PacketDecodeInfo info;
    info.ChallengeParam2 = 0;
    info.BaseHashSize = 32;
    info.SignatureSize = 48;

    PacketChallengeAuthResponseVar p;

    fillPseudoRandomPacket(p.Min);

    p.CertChainHashVector.resize(info.BaseHashSize);
    fillPseudoRandom(p.CertChainHashVector);

    fillPseudoRandom(p.Nonce);

    p.OpaqueDataVector.resize(127);
    fillPseudoRandom(p.OpaqueDataVector);

    p.SignatureVector.resize(info.SignatureSize);
    fillPseudoRandom(p.SignatureVector);

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packetEncodeDecode(p, info));
}

TEST(packet_pseudorandom_encode_decode, PacketChallengeAuthResponseVar_1)
{
    PacketDecodeInfo info;
    info.ChallengeParam2 = 1;
    info.BaseHashSize = 32;
    info.SignatureSize = 48;

    PacketChallengeAuthResponseVar p;

    fillPseudoRandomPacket(p.Min);

    p.CertChainHashVector.resize(info.BaseHashSize);
    fillPseudoRandom(p.CertChainHashVector);

    fillPseudoRandom(p.Nonce);

    p.MeasurementSummaryHashVector.resize(info.BaseHashSize);
    fillPseudoRandom(p.MeasurementSummaryHashVector);

    p.OpaqueDataVector.resize(127);
    fillPseudoRandom(p.OpaqueDataVector);

    p.SignatureVector.resize(info.SignatureSize);
    fillPseudoRandom(p.SignatureVector);

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packetEncodeDecode(p, info));
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
#endif