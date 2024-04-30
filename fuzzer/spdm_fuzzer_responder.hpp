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




#pragma once

#include <iostream>
#include <vector>
#include <list>
#include <functional>

#include <spdmcpp/assert.hpp>
#include <spdmcpp/common.hpp>
#include <spdmcpp/connection.hpp>
#include <spdmcpp/context.hpp>
#include <spdmcpp/helpers.hpp>
#include <spdmcpp/mbedtls_support.hpp>
#include <spdmcpp/mctp_support.hpp>

#include "spdm_fuzzer_config.hpp"
#include "spdm_fuzzer_fixture.hpp"
#include "spdm_fuzzer_predefined_responses.hpp"
#include "config.h"

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)

using namespace spdmcpp;

namespace spdm_wrapper
{
constexpr std::mt19937::result_type mt19937DefaultSeed = 13;

enum class MessageHashEnum : uint8_t
{
    M,
    L,
    NUM
};

// NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class FuzzingResponder
{
  public:
    // NOLINTNEXTLINE cppcoreguidelines-pro-type-member-init
    FuzzingResponder(IOClass &io, TransportClass &trans, const WrapperConfig &config, const PredefinedResponses &predefinedResponses,
        BaseAsymAlgoFlags asymAlgo, BaseHashAlgoFlags hashAlgo, std::istream &str = std::cin):
        io(io), trans(trans), config(config), predefinedResponses(predefinedResponses),
        log(std::cout), asymAlgo(asymAlgo), hashAlgo(hashAlgo), str(str)
    {
        mbedtls_pk_init(&pkctx);
        mbedtls_x509_crt_init(&caCert);
        resetState();
    }

    ~FuzzingResponder()
    {
        mbedtls_x509_crt_free(&caCert);
        mbedtls_pk_free(&pkctx);
    }

    bool sendResponse(RequestResponseEnum expectedResponse, bool &modified);
    void resetState();

  private:
    IOClass &io;
    TransportClass &trans;
    const WrapperConfig &config;
    const PredefinedResponses &predefinedResponses;

    LogClass log;
    const BaseAsymAlgoFlags asymAlgo;
    const BaseHashAlgoFlags hashAlgo;
    std::array<HashClass, static_cast<size_t>(MessageHashEnum::NUM)> Hashes;

    std::istream &str;
    bool readDataFun(char &value)
    {
        //    std::istream &str = config.instructionFilename.empty() ? std::cin : fileStr;
        //bool (*reader)(char &) = [] (char &value) -> bool {
        return (bool) str.get(value);
        //return true
    };

    PacketAlgorithmsResponseVar algoResp;
    mbedtls_pk_context pkctx;
    mbedtls_x509_crt caCert;
    PacketDigestsResponseVar digestResp;
    PacketDecodeInfo info;
    PacketCertificateResponseVar certResp;

    HashClass& getHash(MessageHashEnum hashIdx);

    bool doRandomize(WrapperConfig::Threshold threshold);

    bool fuzzMsgHeader(PacketMessageHeader &header, bool doAlter);

    bool fuzzResponseMessageVersion(PacketVersionResponseVar &msg);
    bool fuzzResponseMessageCapabilities(PacketCapabilitiesResponse &msg);
    bool fuzzResponseMessageAlgorithms(PacketAlgorithmsResponseVar &msg);
    bool fuzzResponseMessageDigest(PacketDigestsResponseVar &msg);
    bool fuzzResponseMessageCertificate(PacketCertificateResponseVar &msg);
    bool fuzzResponseMessageChallengeAuth(PacketChallengeAuthResponseVar &msg);

    bool fuzzResponseMessageMeasurements(PacketMeasurementsResponseVar &msg);
    bool fuzzPacketMeasurementBlockVar(struct PacketMeasurementBlockVar &val, bool doAlter);

    bool getFuzzingData(uint8_t *buf, size_t len);
    bool getFuzzingData(uint8_t &value);
    bool getFuzzingData(uint16_t &value);
    bool getFuzzingData(uint32_t &value);
    bool dropFuzzingData(int len);

    template <typename T>
    bool sendResponseBySource(T& resp, std::function<bool(T&)> fuzzingFunction, WrapperConfig::Threshold threshold, int msgIndex, MessageHashEnum hashIdx = MessageHashEnum::NUM)
    {
        bool modified = false;
        switch (config.source)
        {
        case WrapperConfig::Source::Generator:
            modified = fuzzingFunction(resp);
            sendMessage(resp, hashIdx);
            break;

        case WrapperConfig::Source::RandomStream:
            modified = doRandomize(threshold);
            if (modified)
            {
                sendRandomData(hashIdx);
            }
            else
            {
                sendMessage(resp, hashIdx);
            }
            break;

        case WrapperConfig::Source::File:
            if (!sendPreparedResponse(T::requestResponseCode, hashIdx, msgIndex))
            {
                //abort();
                modified = fuzzingFunction(resp);
                sendMessage(resp, hashIdx);
            }
            else
            {
            //modified = true; //TODO true or false ??? It have to be discussed.
            }
            break;
        }
        return modified;
    }

    template <typename T>
    RetStat sendMessage(T& packet, MessageHashEnum hashIdx = MessageHashEnum::NUM)
    {
        std::vector<uint8_t> buf;
        TransportClass::LayerState lay;

        trans.encodePre(buf, lay);

        size_t start = lay.getEndOffset();
        size_t off = start;
        auto rs = packetEncode(packet, buf, off);
        if (isError(rs))
        {
            return rs;
        }
        if (hashIdx < MessageHashEnum::NUM)
        {
            rs = getHash(hashIdx).update(buf, start);
            if(rs != RetStat::OK) {
                return rs;
            }
        }
        trans.encodePost(buf, lay);

        io.write(buf);
        return rs;
    }

    RetStat sendRandomData(MessageHashEnum hashIdx);
    bool sendPreparedResponse(RequestResponseEnum msgType, MessageHashEnum hashIdx, int msgIndex);


    RetStat updateHash(MessageHashEnum hashIdx = MessageHashEnum::NUM);

    void prepareDefaultResponses();

    static int fRng(void* /*ctx*/, unsigned char* buf, size_t len);

    inline int computeSignature(mbedtls_pk_context* pkctx,
                                std::vector<uint8_t>& signature,
                                const std::vector<uint8_t>& message);

    inline int computeSignature(mbedtls_x509_crt* cert,
                                std::vector<uint8_t>& signature,
                                const std::vector<uint8_t>& message);

    inline void
        fillPseudoRandom(std::span<uint8_t, std::dynamic_extent> buf,
            std::mt19937::result_type seed = mt19937DefaultSeed);

    template <typename T>
    inline void
        fillPseudoRandomType(T& dst,
                            std::mt19937::result_type seed = mt19937DefaultSeed)
    {
        // NOLINTNEXTLINE cppcoreguidelines-pro-type-reinterpret-cast
        fillPseudoRandom(std::span(reinterpret_cast<uint8_t*>(&dst), sizeof(dst)),
                        seed);
    }

    template <typename T>
    inline T
        returnPseudoRandomType(std::mt19937::result_type seed = mt19937DefaultSeed)
    {
        T dst{};
        fillPseudoRandomType(dst, seed);
        return dst;
    }
};

} // namespace spdm_wrapper
