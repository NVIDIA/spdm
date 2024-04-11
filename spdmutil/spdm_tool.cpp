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

/*
 * Copyright (C) NVIDIA Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "spdm_tool.hpp"
#include "str_conv.hpp"
#include "enumerate_endpoints.hpp"
#include <spdmcpp/common.hpp>
#include <spdmcpp/packet.hpp>
#include <CLI/CLI.hpp>
#include <map>
#include <poll.h>

#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>

namespace spdmt {
    using namespace spdmcpp;

    template <class... Ts>
    struct Overloaded : Ts...
    {
        using Ts::operator()...;
    };
    template <class... Ts>
    Overloaded(Ts...) -> Overloaded<Ts...>;

    static constexpr auto numSubCmds = 6U;

    // Constructor
    SpdmTool::SpdmTool()
    : log(std::cout)
    , cmdList(numSubCmds, std::nullopt)
    , mctpIO(log)
    {
        log.setLogLevel(LogClass::Level::Critical);
        packetDecodeInfo.BaseHashSize = defHashAlgoSize;
        packetDecodeInfo.GetMeasurementsParam1 = defMeasParam1;
    }

    // Parse arguments
    auto SpdmTool::parseArgs(int argc, char** argv) -> int
    {
        CLI::App app{"spdmtool, version: 1.0.0"};
        std::string jsonFilename;
        bool debugMode {};
        // Print help
        app.set_help_all_flag("--help-all", "Expand all help");
        // Inteface medium options
        const std::map<std::string, std::string> mediumMap {
            {"pcie", dbusIfcPCIe},
            {"spi", dbusIfcSPI},
            {"i2c", dbusIfcI2C},
            {"usb", dbusIfcUSB },
        };
        app.add_option("-i,--interface", dbusIfc, "Transport medium")
            ->transform(CLI::CheckedTransformer(mediumMap, CLI::ignore_case))
            ->default_str("pcie");
        // Target EID
        app.add_option("-e,--eid", m_eid, "Endpoint EID")
            ->check(CLI::Range(0x00, 0xff));
        // I2C bus number
        int i2cBusNo {6};
        app.add_option("-b,--bus", i2cBusNo, "I2C bus number")
            ->check(CLI::Range(0x00,0xff))
            ->default_str("6");
        // Add option json file
        app.add_option("--json", jsonFilename, "Save responses to JSON file");
        // Add option for the debug tool
        app.add_flag("--debug",  debugMode, "Enable tool debugging");
        // Add option for enumerate endpoints
        app.add_flag("--enumerate", needEnumEps, "Enumerate spdm endpoints");
        // Target subcommands for processing
        auto getVer = app.add_subcommand("get-version", "Get version command");
        auto getCapab = app.add_subcommand("get-capab", "Get capabilities command");
        auto negAlgo =
            app.add_subcommand("neg-algo", "Negotiate algorithm command");
        /* auto getDigest = */
            app.add_subcommand("get-digest", "Get digest command");
        auto getCert = app.add_subcommand("get-cert", "Get certificate command");
        auto getMeas = app.add_subcommand("get-meas", "Get measurements command");
        // Version subcommand config
        VerCmd ver;
        getVer->add_option("--ver", ver.ver, "Version specs")
            ->check(CLI::Range(0x00, 0xff))
            ->default_str("0x10");
        // Get capabilities
        CapabCmd capab;
        getCapab->add_option("--flags", capab.flags, "Capabilities flags")
            ->check(CLI::Range(0x0000'0000, 0x0001'FFFF))
            ->default_str("0x00");
        getCapab->add_option("--exponent", capab.ctExponent, "Capabilities exponent")
            ->check(CLI::Range(0x00, 0xFF))
            ->default_str("0x00");

        // Negotiate algorithm
        NegAlgoCmd algo;
        negAlgo->add_option("--base-asym-algo", algo.baseAsymAlgo, "Base asym algo")
            ->check(CLI::Range(0x0000'0000, 0x0000'0190))
            ->default_str("0x00000080");
        negAlgo->add_option("--base-hash-algo", algo.baseHashAlgo, "Base hash algo")
            ->check(CLI::Range(0x0000'0000, 0x0000'0020))
            ->default_str("0x00000002");

        // Get certificate
        CertCmd cert;
        getCert->add_option("--slot", cert.slot, "Certificate slot")
            ->check(CLI::Range(0, 7))
            ->default_str("0");
        getCert->add_option("--offset", cert.offset, "Certificate offset")
            ->check(CLI::Range(0, 0xFFFF));
        // Get measurements
        MeasCmd meas;
        getMeas
            ->add_option("--attributes", meas.attributes, "Measurement attributes")
            ->check(CLI::Range(0x00, 0x03))
            ->default_str("0x01");
        getMeas
            ->add_option("--block-index", meas.blockIndex,
                        "Measurement block index")
            ->check(CLI::Range(0x00, 0xff))
            ->default_str("0xFE");
        getMeas->add_option("--cert-slot", meas.certSlot, "Certificate slot")
            ->check(CLI::Range(0x00, 0x0f))
            ->default_str("0x0F");

        CLI11_PARSE(app, argc, argv);
        // Configure debug mode
        if (debugMode)
        {
            log.setLogLevel(LogClass::Level::Informational);
        }

        // Check for enum or for normal get values
        if (needEnumEps && (m_eid!=cmdCliInvalid))
        {
            std::cerr << "--eid or --enumerate should be choosen at the same time" << std::endl;
            return EXIT_FAILURE;
        }
        if (!needEnumEps && (m_eid==cmdCliInvalid))
        {
            std::cerr << "--eid argument not specified" << std::endl;
            return EXIT_FAILURE;
        }
        if (dbusIfc == dbusIfcI2C)
        {
            dbusIfc += std::to_string(i2cBusNo);
        }
        // Check if the directory exists and we are able to create file
        if (!jsonFilename.empty())
        {
            jsonFileStream.open(jsonFilename);
            if (!jsonFileStream)
            {
                std::cerr << "Unable to create json file: " << jsonFilename << std::endl;
                return EXIT_FAILURE;
            }
        }
        enum { vpos_ver, vpos_capab, vpos_algo, vpos_dig, vpos_cert, vpos_meas };
        // Subcommands to commands list
        for (auto* subcom : app.get_subcommands())
        {
            auto name = subcom->get_name();
            if (name == "get-version")
            {
                cmdList[vpos_ver] = ver;
            }
            else if (name == "get-capab")
            {
                cmdList[vpos_capab] = capab;
            }
            else if (name == "neg-algo")
            {
                cmdList[vpos_algo] = algo;
            }
            else if (name == "get-digest")
            {
                cmdList[vpos_dig] = DigestCmd{};
            }
            else if (name == "get-cert")
            {
                cmdList[vpos_cert] = cert;
            }
            else if (name == "get-meas")
            {
                cmdList[vpos_meas] = meas;
            }
            else
            {
                throw std::logic_error("Unhandled cmdline command");
            }
        }
        if( app.get_subcommands().size() > 0 )
        {
            auto it = std::find_if(cmdList.rbegin(), cmdList.rend(), [](const auto& opt) {
                return opt.has_value();
            });
            if (it == cmdList.rend())
            {
                return EXIT_SUCCESS;
            }
            const auto idx = std::min<size_t>(std::distance(it, cmdList.rend()) - 1U, cmdList.size());
            for (size_t i=0; i<idx; ++i)
            {
                if (cmdList[i])
                {
                    continue;
                }
                if( i==vpos_ver )
                {
                    cmdList[i] = VerCmd{};
                }
                else if ( i==vpos_capab )
                {
                    cmdList[i] = CapabCmd{};
                }
                else if ( i==vpos_algo )
                {
                    cmdList[i] = NegAlgoCmd{};
                }
                else if ( i==vpos_dig )
                {
                    cmdList[i] = DigestCmd{};
                }
                else if ( i==vpos_cert )
                {
                    cmdList[i] = CertCmd{};
                }
                else if( i==vpos_meas )
                {
                    cmdList[i] = MeasCmd{};
                }
            }
        }
        return EXIT_SUCCESS;
    }

    template <>
    spdmcpp::RetStat SpdmTool::handleRecv<PacketVersionResponseVar>(std::vector<uint8_t>& buf)
    {
        PacketVersionResponseVar resp;
        auto rs = interpretResponse(buf, resp);
        if (isError(rs))
        {
            jsonGen["GetVersion"] = { {"ResponseCode", get_cstr(rs)}};
            return rs;
        }
        std::vector<std::string> svers;
        svers.reserve(resp.VersionNumberEntries.size());
        for(const auto& ver: resp.VersionNumberEntries)
        {
            svers.push_back(verToString(ver));
        }
        jsonGen["GetVersion"] = {
            { "SPDMVersion", svers },
            {"ResponseCode", get_cstr(rs) }
        };
        return rs;
    }

    template <>
    spdmcpp::RetStat SpdmTool::handleRecv<PacketCapabilitiesResponse>(std::vector<uint8_t>& buf)
    {
        PacketCapabilitiesResponse resp;
        auto rs = interpretResponse(buf, resp);
        if (isError(rs))
        {
            jsonGen["GetCapabilities"] = {
                {"ResponseCode", get_cstr(rs) }
            };
            return rs;
        }
        jsonGen["GetCapabilities"] = {
            { "SPDMVersion", verToString(resp.Header.MessageVersion) },
            { "CTExponent",  resp.CTExponent },
            { "Capabilities", capFlagsToStr(resp.Flags) },
            {"ResponseCode", get_cstr(rs) }
        };
        return rs;
    }

    template <>
    spdmcpp::RetStat SpdmTool::handleRecv<PacketAlgorithmsResponseVar>(std::vector<uint8_t>& buf)
    {
        PacketAlgorithmsResponseVar resp;
        auto rs = interpretResponse(buf, resp);
        do
        {
            if (isError(rs))
            {
                break;
            }
            if (auto hsize = getHashSize(resp.Min.BaseHashAlgo);
                hsize != invalidFlagSize)
            {
                packetDecodeInfo.BaseHashSize = hsize;
            }
            else
            {
                rs = RetStat::ERROR_INVALID_FLAG_SIZE;
                break;
            }
            if (auto ssize = getSignatureSize(resp.Min.BaseAsymAlgo);
                ssize != invalidFlagSize)
            {
                packetDecodeInfo.SignatureSize = ssize;
            }
            else
            {
                rs =  RetStat::ERROR_INVALID_FLAG_SIZE;
                break;
            }
        } while(false);

        if (isError(rs))
        {
            jsonGen["NegotiateAlgorithms"] = {
                {"ResponseCode", get_cstr(rs) }
            };
            return rs;
        }
        algoResp = resp;
        jsonGen["NegotiateAlgorithms"] = {
            {"SPDMVersion", verToString(resp.Min.Header.MessageVersion)},
            {"SignatureAlgorithm", asymAlgoToStr(resp.Min.BaseAsymAlgo)},
            {"HashingAlgorithm", hashAlgoToStr(resp.Min.BaseHashAlgo)},
            {"ResponseCode", get_cstr(rs) }
        };
        return rs;
    }

    template <>
    spdmcpp::RetStat SpdmTool::handleRecv<PacketCertificateResponseVar>(std::vector<uint8_t>& buf)
    {
        PacketCertificateResponseVar resp;
        auto rs = interpretResponse(buf, resp);
        if (wholeCert)
        {
            if (certBuf.empty())
            { // first chunk so reserve space for what's expected to come
                certBuf.reserve(resp.Min.PortionLength + resp.Min.RemainderLength);
            }
            { // store chunk data
                auto off = certBuf.end() - certBuf.begin();
                certBuf.resize(off + resp.Min.PortionLength);
                std::copy(resp.CertificateVector.begin(),
                          resp.CertificateVector.end(),
                          std::next(certBuf.begin(), off));
            }
            if (!resp.Min.RemainderLength)
            {
                wholeCert = false;
                std::string certTxt;
                rs = parseCertChain(certBuf, certTxt);
                if (isError(rs))
                {
                    jsonGen["GetCertificate"] = {{"ResponseCode", get_cstr(rs)}};
                    return rs;
                }
                jsonGen["GetCertificate"] = {
                    {"SPDMVersion", verToString(resp.Min.Header.MessageVersion)},
                    {"ResponseCode", get_cstr(rs)},
                    {"Slot", resp.Min.Header.Param1},
                    {"CertChain", certTxt}};
            }
        }
        else
        {
            if (isError(rs))
            {
                jsonGen["GetCertificate"] = {{"ResponseCode", get_cstr(rs)}};
                return rs;
            }
            jsonGen["GetCertificate"] = {
                {"SPDMVersion", verToString(resp.Min.Header.MessageVersion)},
                {"ResponseCode", get_cstr(rs)},
                {"Slot", resp.Min.Header.Param1},
                {"CertChunk:", resp.CertificateVector}};
        }
        return rs;
    }

    template <>
    spdmcpp::RetStat SpdmTool::handleRecv<PacketDigestsResponseVar>(std::vector<uint8_t>& buf)
    {
        PacketDigestsResponseVar resp;
        auto rs = interpretResponse(buf, resp, packetDecodeInfo);
        if (isError(rs))
        {
            jsonGen["GetDigest"] = {
                {"ResponseCode", get_cstr(rs) }
            };
            return rs;
        }
        std::vector<std::vector<int>> digest;
        digest.reserve(resp.Digests.size());
        std::transform(resp.Digests.begin(), resp.Digests.end(), std::back_inserter(digest),
            [](const std::vector<uint8_t> &vec) {
                std::vector<int> temp;
                temp.reserve(vec.size());
                std::transform(vec.begin(), vec.end(), std::back_inserter(temp),
                                [](uint8_t val) { return static_cast<int>(val); });
                return temp;
        });
        jsonGen["GetDigest"] = {
            {"SPDMVersion", verToString(resp.Min.Header.MessageVersion)},
            {"ResponseCode", get_cstr(rs) },
            {"Slot", resp.Min.Header.Param1 },
            {"Digest", digest }
        };
        return rs;
    }

    template <>
    spdmcpp::RetStat SpdmTool::handleRecv<PacketMeasurementsResponseVar>(std::vector<uint8_t>& buf)
    {
        PacketMeasurementsResponseVar resp;
        auto rs = interpretResponse(buf, resp, packetDecodeInfo);
        if (isError(rs))
        {
            jsonGen["GetMeasurement"] = {
                {"ResponseCode", get_cstr(rs) }
            };
            return rs;
        }
        std::vector<std::pair<int,std::vector<uint8_t>>> meas;
        meas.reserve(resp.MeasurementBlockVector.size());
        for (const auto& v : resp.MeasurementBlockVector)
        {
            meas.emplace_back(v.Min.Index,v.MeasurementVector);
        }
        jsonGen["GetMeasurement"] = {
            {"SPDMVersion", verToString(resp.Min.Header.MessageVersion)},
            {"ResponseCode", get_cstr(rs) },
            {"Slot", resp.Min.Header.Param2},
            {"MeasurementRecordLength", resp.Min.getMeasurementRecordLength() },
            {"MeasurementData",  meas},
            {"Nonce", resp.Nonce },
            {"Signature", resp.SignatureVector }
        };
        return rs;
    }

    template <>
    spdmcpp::RetStat SpdmTool::handleRecv<PacketChallengeAuthResponseVar>(std::vector<uint8_t>& buf)
    {
        PacketChallengeAuthResponseVar resp;
        auto rs = interpretResponse(buf, resp, packetDecodeInfo);
        return rs;
    }

    // SPDM tool main loop
    auto SpdmTool::runComm() -> bool
    {
        if (std::all_of(cmdList.begin(), cmdList.end(),
                [](const std::optional<cmdv>& opt) {
                    return !opt.has_value();}))
        {
            return true;
        }
        try
        {
            transport = std::make_unique<MctpTransportClass>(m_eid);
            if (!transport)
            {
                std::cerr << "Unable to create transport class" << std::endl;
                return false;
            }
            connectMctp();
        }
        catch (const std::exception& e)
        {
            std::cerr << "Error: " << e.what() << std::endl;
            return false;
        }
        RetStat rs {};
        auto fret { true };
        for (const auto& v : cmdList)
        {
            std::vector<uint8_t> sendBuf, recvBuf;
            if (!v)
            {
                break;
            }
            std::visit(
                Overloaded{
                    [&sendBuf, &rs, this](const VerCmd& arg)
                    {
                        PacketGetVersionRequest req{};
                        if (arg.ver == 0x10)
                        {
                            req.Header.MessageVersion =
                                MessageVersionEnum::SPDM_1_0;
                        }
                        else
                        {
                            req.Header.MessageVersion =
                                MessageVersionEnum::SPDM_1_1;
                        }
                        rs = prepareRequest(req, sendBuf);
                    },
                    [&sendBuf, &rs, this](const CapabCmd& arg)
                    {
                        PacketGetCapabilitiesRequest req{};
                        req.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;
                        req.Flags =
                            static_cast<RequesterCapabilitiesFlags>(arg.flags);
                        req.CTExponent = arg.ctExponent;
                        rs = prepareRequest(req, sendBuf);
                    },
                    [&sendBuf, &rs, this](const NegAlgoCmd& arg)
                    {
                        PacketNegotiateAlgorithmsRequestVar req{};
                        req.Min.Length = 32;
                        req.Min.Header.MessageVersion =
                            MessageVersionEnum::SPDM_1_1;
                        req.Min.MeasurementSpecification = 0x01;
                        req.Min.BaseAsymAlgo =
                            static_cast<BaseAsymAlgoFlags>(arg.baseAsymAlgo);
                        req.Min.BaseHashAlgo =
                            static_cast<BaseHashAlgoFlags>(arg.baseHashAlgo);
                        rs = prepareRequest(req, sendBuf);
                    },
                    [&sendBuf, &rs, this](const CertCmd& arg)
                    {
                        PacketGetCertificateRequest req{};
                        req.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;
                        req.Header.Param1 = arg.slot;
                        certSlot = arg.slot;
                        if (arg.needChain())
                        {
                            certBuf.clear();
                            req.Offset = certBuf.size();
                            wholeCert = true;
                        }
                        else
                        {
                            req.Offset = arg.offset;
                        }
                        req.Length = std::numeric_limits<uint16_t>::max();
                        rs = prepareRequest(req, sendBuf);
                    },
                    [&sendBuf, &rs, this](const MeasCmd& arg)
                    {
                        PacketGetMeasurementsRequestVar req{};
                        req.Min.Header.MessageVersion =
                            MessageVersionEnum::SPDM_1_1;
                        req.Min.Header.Param1 =  packetDecodeInfo.GetMeasurementsParam1 =  arg.attributes;
                        req.Min.Header.Param2 = arg.blockIndex;
                        req.SlotIDParam = arg.certSlot;
                        req.setNonce();
                        rs = prepareRequest(req, sendBuf);
                    },
                    [&sendBuf, &rs, this](const DigestCmd&)
                    {
                        PacketGetDigestsRequest req;
                        req.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;
                        rs = prepareRequest(req, sendBuf);
                    }},
                *v);
            do
            {   if (wholeCert)
                {
                    PacketGetCertificateRequest req {};
                    req.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;
                    req.Header.Param1 = certSlot;
                    req.Offset = certBuf.size();
                    req.Length = std::numeric_limits<uint16_t>::max();
                    rs = prepareRequest(req, sendBuf);
                }
                if (isError(rs))
                {
                    log.iprint("Unable to decode packet rs=");
                    log.println(rs);
                    fret = false;
                    break;
                }
                if (rs = sendMctp(sendBuf); rs != RetStat::OK)
                {
                    log.iprint("Unable to send packet rs=");
                    log.println(rs);
                    fret = false;
                    break;
                }
                if (rs = recvMctp(recvBuf); rs != RetStat::OK)
                {
                    log.iprint("Unable to rcv packet rs=");
                    log.println(rs);
                    fret = false;
                    break;
                }
                if (rs = parseResp(recvBuf); isError(rs))
                {
                    log.iprint("Unable to parse packet rs=");
                    log.println(rs);
                    fret = false;
                    break;
                }
            }
            while(wholeCert);
        }
        return fret;
    }

    // Send request and parse response
    auto SpdmTool::parseResp(std::vector<uint8_t>& buf) -> spdmcpp::RetStat
    {
        if (log.logLevel >= spdmcpp::LogClass::Level::Informational)
        {
            log.iprint("ResponseBuffer.size() = ");
            log.println(buf.size());
            log.iprint("ResponseBuffer = ");
            log.println(buf);
        }
        MessageVersionEnum version {};
        RequestResponseEnum code {};
        TransportClass::LayerState lay {};
        auto rs = transport->decode(buf, lay);
        if (isError(rs))
        {
            return rs;
        }
        auto responseBufferSPDMOffset = lay.getEndOffset();
        if (buf.size() - responseBufferSPDMOffset < sizeof(PacketMessageHeader))
        {
            return RetStat::ERROR_BUFFER_TOO_SMALL;
        }
        version =
            packetMessageHeaderGetMessageVersion(buf, responseBufferSPDMOffset);
        code = packetMessageHeaderGetRequestresponsecode(buf,
                                                        responseBufferSPDMOffset);
        if (log.logLevel >= spdmcpp::LogClass::Level::Informational)
        {
            log.print("packetVersion= ");
            log.println(version);
        }
        // "custom" response handling for ERRORS
        if (code == RequestResponseEnum::RESPONSE_ERROR)
        {
            log.iprintln("RESPONSE_ERROR");
            PacketErrorResponseVar err;
            rs = interpretResponse(buf, err);
            if (isError(rs))
            {
                log.iprint("Interpret response error ");
                log.iprintln(rs);
            }
            return RetStat::ERROR_RESPONSE;
        }
        if (code == RequestResponseEnum::RESPONSE_VERSION)
        {
            // version response is what sets the MessageVersion, so it has to be
            // handled separately from the packets below
            rs = handleRecv<PacketVersionResponseVar>(buf);
        }
        else
        {
            if(code != PacketCertificateResponseVar::requestResponseCode && wholeCert) {
                return RetStat::ERROR_WRONG_REQUEST_RESPONSE_CODE;
            }
            switch (code)
            {
                case PacketCapabilitiesResponse::requestResponseCode:
                    rs = handleRecv<PacketCapabilitiesResponse>(buf);
                    break;
                case PacketAlgorithmsResponseVar::requestResponseCode:
                    rs = handleRecv<PacketAlgorithmsResponseVar>(buf);
                    break;
                case PacketDigestsResponseVar::requestResponseCode:
                    rs = handleRecv<PacketDigestsResponseVar>(buf);
                    break;
                case PacketCertificateResponseVar::requestResponseCode:
                    rs = handleRecv<PacketCertificateResponseVar>(buf);
                    break;
                case PacketChallengeAuthResponseVar::requestResponseCode:
                    rs = handleRecv<PacketChallengeAuthResponseVar>(buf);
                    break;
                case PacketMeasurementsResponseVar::requestResponseCode:
                    rs = handleRecv<PacketMeasurementsResponseVar>(buf);
                    break;
                default:
                    log.iprint("Unknown code: ");
                    log.println(code);
                    return RetStat::ERROR_UNKNOWN_REQUEST_RESPONSE_CODE;
            }
        }
        return rs;
    }

    // Try connect MCTP
    auto SpdmTool::connectMctp() -> void
    {
        EnumerateEndpoints enumerate(dbusIfc);
        auto& respInfo = enumerate.getRespondersInfo();
        if (respInfo.empty() || respInfo.back().sockPath.empty())
        {
            throw std::logic_error("Unable to get transport socket");
        }
        const auto& unixSock =  respInfo.back().sockPath;
        if (!mctpIO.createSocket(unixSock))
        {
            using namespace std::string_literals;
            throw std::logic_error(
                "Unable connect to MCTP socket "s + unixSock.substr(1)
            );
        }
    }
    // Recv data over MCTP with timeout
    auto SpdmTool::recvMctp(std::vector<uint8_t>& buf) -> spdmcpp::RetStat
    {
        static constexpr auto timeout = 180'000U;
        std::array<pollfd,1> pfd{};
        pfd[0].fd = mctpIO.getSocket();
        pfd[0].events = POLLIN;
        auto ret = ::poll(pfd.data(), 1, timeout);
        if (ret == -1)
        {
            throw std::logic_error("Poll error");
        }
        if (ret == 0)
        {
            return RetStat::ERROR_TIMEOUT;
        }
        return mctpIO.read(buf);
    }
    // Send data over MCTP
    auto SpdmTool::sendMctp(const std::vector<uint8_t>& buf) -> spdmcpp::RetStat
    {
        if (log.logLevel >= spdmcpp::LogClass::Level::Informational)
        {
            log.print("sendBufer.size() = ");
            log.println(buf.size());
            log.print("sendBufer = ");
            log.println(buf);
        }
        return mctpIO.write(buf);
    }

    //! Parse certificate chain
    auto SpdmTool::parseCertChain(std::vector<uint8_t>& vec, std::string& out) -> spdmcpp::RetStat
    {
        PacketCertificateChain certChain;
        size_t off = 0;
        auto rs = packetDecodeInternal(log, certChain, vec, off);
        if (isError(rs))
        {

            return rs;
        }
        if (certChain.Length != vec.size())
        {
            return RetStat::ERROR_CERTIFICATE_CHAIN_SIZE_INVALID;
        }
        if (!algoResp)
        {
            return RetStat::ERROR_INVALID_FLAG_SIZE;
        }
        std::vector<uint8_t> rootCertHash;
        {
            if (auto hsize = getHashSize(algoResp->Min.BaseHashAlgo);
                hsize != invalidFlagSize)
            {
                rootCertHash.resize(hsize);
            }
            else
            {
                return RetStat::ERROR_INVALID_FLAG_SIZE;
            }
            rs = packetDecodeBasic(log, rootCertHash, vec, off);
            if (isError(rs))
            {
                return rs;
            }
        }
        do
        {
            mbedtls_x509_crt cert;
            mbedtls_x509_crt_init(&cert);
            auto ret =
                mbedtls_x509_crt_parse_der(&cert, &vec[off], vec.size() - off);
            if (ret)
            {
                mbedtls_x509_crt_free(&cert);
                return RetStat::ERROR_CERTIFICATE_PARSING_ERROR;
            }
            size_t asn1Len = 0;
            {
                auto s = &vec[off];
                auto p = s;
                ret = mbedtls_asn1_get_tag(&p, &vec[vec.size()],
                    &asn1Len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
                if (ret)
                {
                    mbedtls_x509_crt_free(&cert);
                    return RetStat::ERROR_CERTIFICATE_PARSING_ERROR;
                }
                asn1Len += (p - s);
            }
            size_t sz {};
            off += asn1Len;
            std::array<unsigned char, 8192> buf {{}};
            ret = mbedtls_pem_write_buffer(
                "-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n",
                cert.raw.p, cert.raw.len, buf.data(), buf.size(), &sz);
            if(ret) {
                return RetStat::ERROR_CERTIFICATE_PARSING_ERROR;
            }
            if (sz >= buf.size())
            {
                return RetStat::ERROR_CERTIFICATE_PARSING_ERROR;
            }
            buf[sz] = '\0';
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            out += reinterpret_cast<char*>(buf.data());
            mbedtls_x509_crt_free(&cert);
        } while (off < vec.size());
        return rs;
    }

    // Run app
    auto SpdmTool::run() -> bool
    {
        bool ret {};
        do
        {
            ret = runEnumerate();
            if (!ret) 
            {
                break;
            }
            ret = runComm();
            if (!ret)
            {
                break;
            }
            if (!jsonGen.empty())
            {
                if (jsonFileStream.is_open())
                {
                    jsonFileStream << jsonGen << std::endl;
                }
                else
                {
                    std::cout << jsonGen << std::endl;
                }
            }
        } while(false);
        return ret;
    }


    // Run enumerate
    auto SpdmTool::runEnumerate() -> bool
    {
        if (!needEnumEps)
        {
            return true;
        }
        EnumerateEndpoints eobj(dbusIfc);
        for (const auto& epInfo : eobj.getRespondersInfo())
        {
            jsonGen["Endpoints"].push_back(
                {{"Path", epInfo.path}, {"EID", epInfo.eid}, {"UUID", epInfo.uuid}});
        }
        if (jsonFileStream)
        {
            jsonFileStream << jsonGen << std::endl;
        }
        return true;
    }

}
