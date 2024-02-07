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
#pragma once

#include <spdmcpp/common.hpp>
#include "cmds.hpp"
#include <memory>
#include <vector>
#include <optional>
#include <spdmcpp/mctp_support.hpp>
#include <spdmcpp/log.hpp>
#include <nlohmann/json.hpp>
#include <fstream>
#include <optional>

namespace spdmt
{
    class SpdmTool
    {
        static constexpr auto defHashAlgoSize = 48U;
        static constexpr auto defMeasParam1 = 11;
    public:
        SpdmTool(SpdmTool&) = delete;
        SpdmTool& operator=(SpdmTool&) = delete;
        SpdmTool(SpdmTool&&) = delete;
        SpdmTool& operator=(SpdmTool&&) = delete;
        SpdmTool();
        ~SpdmTool() = default;
        //! Argument parser
        auto parseArgs(int argc, char** argv) -> int;
        //! Main loop
        auto run() -> bool;

    private:
        // Run communication
        auto runComm() -> bool;
        // Run enumerate
        auto runEnumerate() -> bool;
        //! Connect to mctp
        auto connectMctp() -> void;
        //! Send data over MCTP
        auto sendMctp(const std::vector<uint8_t>& buf) -> spdmcpp::RetStat;
        //! Recv data over MCTP
        auto recvMctp(std::vector<uint8_t>& buf) -> spdmcpp::RetStat;

        //! Generate request
        template <typename T>
        auto prepareRequest(const T& packet, std::vector<uint8_t>& buf)
            -> spdmcpp::RetStat;

        //! Interpret response
        template <typename T, typename... Targs>
        auto interpretResponse(std::vector<uint8_t>& buf, T& packet, Targs... fargs) -> spdmcpp::RetStat;

        //! Parse response
        auto parseResp(std::vector<uint8_t>& buf) -> spdmcpp::RetStat;

        //! Handle receive data
        template <class T>
        [[nodiscard]] spdmcpp::RetStat handleRecv(std::vector<uint8_t>& buf);

        //! Parse certificate chain
        auto parseCertChain(std::vector<uint8_t>& vec, std::string &out) -> spdmcpp::RetStat;

    private:
        static constexpr auto cmdCliInvalid = -1;
        static constexpr auto dbusIfcPCIe = "xyz.openbmc_project.MCTP.Control.PCIe";
        static constexpr auto dbusIfcSPI = "xyz.openbmc_project.MCTP.Control.SPI";
        static constexpr auto dbusIfcUSB = "xyz.openbmc_project.MCTP.Control.USB";
        static constexpr auto dbusIfcI2C = "xyz.openbmc_project.MCTP.Control.SMBus";
        //! Logger
        spdmcpp::LogClass log;
        // Selected medium
        std::string dbusIfc { dbusIfcPCIe };
        // Current request with args
        std::vector<std::optional<cmdv>> cmdList;
        // Connection class
        spdmcpp::MctpIoClass mctpIO;
        //! Target EID
        int m_eid {cmdCliInvalid};
        // Save to json
        std::ofstream jsonFileStream;
        // Json object
        nlohmann::json jsonGen;
        // MCTP transport
        std::unique_ptr<spdmcpp::MctpTransportClass> transport;
        // Packet decode info
        spdmcpp::PacketDecodeInfo packetDecodeInfo;
        // Retrive whole cert
        bool wholeCert {};
        //! Certificate buffer
        std::vector<uint8_t> certBuf;
        // Certifcate slot
        uint8_t certSlot {};
        std::optional<spdmcpp::PacketAlgorithmsResponseVar> algoResp;
        //! Need enumerate
        bool needEnumEps {};
    };

    //! Prepare request
    template <typename T>
    auto SpdmTool::prepareRequest(const T& packet, std::vector<uint8_t>& buf)
        -> spdmcpp::RetStat
    {
        using namespace spdmcpp;
        if (log.logLevel >= spdmcpp::LogClass::Level::Informational)
        {
            log.iprint("sendRequest(");
            log.print(typeid(packet).name());
            log.println("):");
            packet.printMl(log);
        }
        TransportClass::LayerState lay;
        if (transport)
        {
            transport->encodePre(buf, lay);
        }
        auto rs = packetEncode(packet, buf, lay.getEndOffset());
        if (isError(rs))
        {
            return rs;
        }
        if (transport)
        {
            transport->encodePost(buf, lay);
        }
        return RetStat::OK;
    }

    //! Interpret response
    template <typename T, typename... Targs>
    auto SpdmTool::interpretResponse(std::vector<uint8_t>& buf, T& packet, Targs... fargs) -> spdmcpp::RetStat
    {
        using namespace spdmcpp;
        TransportClass::LayerState lay;
        if (transport)
        {
            transport->decode(buf, lay);
        }
        size_t off = lay.getEndOffset();
        auto rs = packetDecode(log, packet, buf, off, fargs...);
        if (isError(rs))
        {
            if (rs == RetStat::ERROR_WRONG_REQUEST_RESPONSE_CODE)
            {
                log.iprint("wrong code is: ");
                log.println(packetMessageHeaderGetRequestresponsecode(
                    buf, lay.getEndOffset()));
            }
            return rs;
        }

        if (log.logLevel >= spdmcpp::LogClass::Level::Informational)
        {
            log.iprint("interpretResponse(");
            log.print(typeid(packet).name());
            log.println("):");
            packet.printMl(log);
        }
        return rs;
    }

}
