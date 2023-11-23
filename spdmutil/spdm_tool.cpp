#include "spdm_tool.hpp"
#include <spdmcpp/common.hpp>
#include <spdmcpp/packet.hpp>
#include <CLI/CLI.hpp>
#include <map>
#include <poll.h>

namespace spdmt {
    using namespace spdmcpp;

    template <class... Ts>
    struct Overloaded : Ts...
    {
        using Ts::operator()...;
    };
    template <class... Ts>
    Overloaded(Ts...) -> Overloaded<Ts...>;

    // Constructor
    SpdmTool::SpdmTool() : log(std::cout), mctpIO(log)
    {
        log.setLogLevel(LogClass::Level::Informational);
        packetDecodeInfo.BaseHashSize = defHashAlgoSize;
        packetDecodeInfo.GetMeasurementsParam1 = defMeasParam1;
    }

    // Parse arguments
    auto SpdmTool::parseArgs(int argc, char** argv) -> int
    {
        CLI::App app{"spdmtool, version: 1.0.0"};
        // Print help
        app.set_help_all_flag("--help-all", "Expand all help");
        // Inteface medium options
        const std::map<std::string, TransportMedium> mediumMap{
            {"pcie", TransportMedium::PCIe},
            {"spi", TransportMedium::SPI},
            {"i2c", TransportMedium::I2C}};
        app.add_option("-i,--interface", medium, "Transport medium")
            ->transform(CLI::CheckedTransformer(mediumMap, CLI::ignore_case))
            ->default_str("pcie");
        // Target EID
        app.add_option("-e,--eid", m_eid, "Endpoint EID")
            ->check(CLI::Range(0x00, 0xff))
            ->required();
        // I2C bus number
        app.add_option("-b,--bus", m_i2c_bus_no, "I2C bus number")
            ->check(CLI::Range(0x00,0xff))
            ->default_str("6");

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
        VerCmd ver{0x10};
        getVer->add_option("--ver", ver.ver, "Version specs")
            ->check(CLI::Range(0x00, 0xff))
            ->default_str("0x10");

        // Get capabilities
        CapabCmd capab{0x00, 0x00};
        getCapab->add_option("--flags", capab.flags, "Capabilities flags")
            ->check(CLI::Range(0x0000'0000, 0x0001'FFFF))
            ->default_str("0x00");
        getCapab->add_option("--exponent", capab.ctExponent, "Capabilities exponent")
            ->check(CLI::Range(0x00, 0xFF))
            ->default_str("0x00");

        // Negotiate algorithm
        NegAlgoCmd algo{0x0000'0190, 0x0000'0007};
        negAlgo->add_option("--base-asym-algo", algo.baseAsymAlgo, "Base asym algo")
            ->check(CLI::Range(0x0000'0000, 0x0000'0190))
            ->default_str("0x00000090");
        negAlgo->add_option("--base-hash-algo", algo.baseHashAlgo, "Base hash algo")
            ->check(CLI::Range(0x0000'0000, 0x0000'0020))
            ->default_str("0x00000007");

        // Get certificate
        CertCmd cert{0,0};
        getCert->add_option("--slot", cert.slot, "Certificate slot")
            ->check(CLI::Range(0, 7))
            ->default_str("0");
        getCert->add_option("--offset", cert.offset, "Certificate offset")
            ->check(CLI::Range(0, 0xFFFF))
            ->default_str("0");
        // Get measurements
        MeasCmd meas{0x01, 0xFE, 0x00};
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
        // Subcommands to commands list
        for (auto* subcom : app.get_subcommands())
        {
            auto name = subcom->get_name();
            if (name == "get-version")
            {
                cmdList.emplace_back(ver);
            }
            else if (name == "get-capab")
            {
                cmdList.emplace_back(capab);
            }
            else if (name == "neg-algo")
            {
                cmdList.emplace_back(algo);
            }
            else if (name == "get-cert")
            {
                cmdList.emplace_back(cert);
            }
            else if (name == "get-meas")
            {
                cmdList.emplace_back(meas);
            }
            else if (name == "get-digest")
            {
                cmdList.emplace_back(DigestCmd{});
            }
            else
            {
                throw std::logic_error("Unhandled cmdline command");
            }
        }
        return 0;
    }

    template <>
    spdmcpp::RetStat SpdmTool::handleRecv<PacketVersionResponseVar>(std::vector<uint8_t>& buf)
    {
        PacketVersionResponseVar resp;
        auto rs = interpretResponse(buf, resp);
        return rs;
    }

    template <>
    spdmcpp::RetStat SpdmTool::handleRecv<PacketCapabilitiesResponse>(std::vector<uint8_t>& buf)
    {
        PacketCapabilitiesResponse resp;
        auto rs = interpretResponse(buf, resp);
        return rs;
    }

    template <>
    spdmcpp::RetStat SpdmTool::handleRecv<PacketAlgorithmsResponseVar>(std::vector<uint8_t>& buf)
    {
        PacketAlgorithmsResponseVar resp;
        auto rs = interpretResponse(buf, resp);
        if (isError(rs))
        {
            return rs;
        }
        if (auto hsize = getHashSize(resp.Min.BaseHashAlgo);
            hsize != invalidFlagSize)
        {
            packetDecodeInfo.BaseHashSize = hsize;
        }
        else
        {
            return RetStat::ERROR_INVALID_FLAG_SIZE;
        }
        if (auto ssize = getSignatureSize(resp.Min.BaseAsymAlgo);
            ssize != invalidFlagSize)
        {
            packetDecodeInfo.SignatureSize = ssize;
        }
        else
        {
            return RetStat::ERROR_INVALID_FLAG_SIZE;
        }
        return rs;
    }

    template <>
    spdmcpp::RetStat SpdmTool::handleRecv<PacketCertificateResponseVar>(std::vector<uint8_t>& buf)
    {
        PacketCertificateResponseVar resp;
        auto rs = interpretResponse(buf, resp);
        return rs;
    }

    template <>
    spdmcpp::RetStat SpdmTool::handleRecv<PacketDigestsResponseVar>(std::vector<uint8_t>& buf)
    {
        PacketDigestsResponseVar resp;
        auto rs = interpretResponse(buf, resp, packetDecodeInfo);
        return rs;
    }

    template <>
    spdmcpp::RetStat SpdmTool::handleRecv<PacketMeasurementsResponseVar>(std::vector<uint8_t>& buf)
    {
        PacketMeasurementsResponseVar resp;
        auto rs = interpretResponse(buf, resp, packetDecodeInfo);
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
    auto SpdmTool::run() -> bool
    {
        if (cmdList.empty())
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
        for (const auto& v : cmdList)
        {
            std::vector<uint8_t> sendBuf, recvBuf;
            std::visit(
                Overloaded{
                    [&sendBuf, &rs, this](const VerCmd& arg) {
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
                    [&sendBuf, &rs, this](const CapabCmd& arg) {
                        PacketGetCapabilitiesRequest req{};
                        req.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;
                        req.Flags =
                            static_cast<RequesterCapabilitiesFlags>(arg.flags);
                        req.CTExponent = arg.ctExponent;
                        rs = prepareRequest(req, sendBuf);
                    },
                    [&sendBuf, &rs, this](const NegAlgoCmd& arg) {
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
                    [&sendBuf, &rs, this](const CertCmd& arg) {
                        PacketGetCertificateRequest req{};
                        req.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;
                        req.Header.Param1 = arg.slot;
                        req.Offset = arg.offset;
                        req.Length = std::numeric_limits<uint16_t>::max();
                        rs = prepareRequest(req, sendBuf);
                    },
                    [&sendBuf, &rs, this](const MeasCmd& arg) {
                        PacketGetMeasurementsRequestVar req{};
                        req.Min.Header.MessageVersion =
                            MessageVersionEnum::SPDM_1_1;
                        req.Min.Header.Param1 =  packetDecodeInfo.GetMeasurementsParam1 =  arg.attributes;
                        req.Min.Header.Param2 = arg.blockIndex;
                        req.SlotIDParam = arg.certSlot;
                        req.setNonce();
                        rs = prepareRequest(req, sendBuf);
                    },
                    [&sendBuf, &rs, this](const DigestCmd&) {
                        PacketGetDigestsRequest req;
                        req.Header.MessageVersion = MessageVersionEnum::SPDM_1_1;
                        rs = prepareRequest(req, sendBuf);
                    }},
                v);
            if (isError(rs))
            {
                log.iprint("Unable to decode packet rs=");
                log.println(rs);
                return false;
            }
            if (rs=sendMctp(sendBuf); rs != RetStat::OK)
            {
                log.iprint("Unable to send packet rs=");
                log.println(rs);
                return false;
            }
            if (rs=recvMctp(recvBuf); rs != RetStat::OK)
            {
                log.iprint("Unable to rcv packet rs=");
                log.println(rs);
                return false;
            }
            if (rs= parseResp(recvBuf);  isError(rs))
            {
                log.iprint("Unable to parse packet rs=");
                log.println(rs);
                return false;
            }
        }
        return true;
    }

    // Send request and parse response
    auto SpdmTool::parseResp(std::vector<uint8_t>& buf) -> spdmcpp::RetStat
    {
        log.iprint("ResponseBuffer.size() = ");
        log.println(buf.size());
        log.iprint("ResponseBuffer = ");
        log.println(buf);
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
        log.print("packetVersion= ");
        log.println(version);

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
            switch (code)
            { // clang-format off
            // NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
            #define DTYPE(type)                                                            \
                case type::requestResponseCode:                                            \
                    rs = handleRecv<type>(buf);                                            \
                    break;
                DTYPE(PacketCapabilitiesResponse)
                DTYPE(PacketAlgorithmsResponseVar)
                DTYPE(PacketDigestsResponseVar)
                DTYPE(PacketCertificateResponseVar)
                DTYPE(PacketChallengeAuthResponseVar)
                DTYPE(PacketMeasurementsResponseVar)
                default:
                    log.iprint("!!! Unknown code: ");
                    log.println(code);
                    return RetStat::ERROR_UNKNOWN_REQUEST_RESPONSE_CODE;
            #undef DTYPE
            } // clang-format on
        }
        return rs;
    }

    // Try connect MCTP
    auto SpdmTool::connectMctp() -> void
    {
        using namespace std::string_literals;
        std::string sockName;
        switch (medium)
        {
            case TransportMedium::PCIe:
                sockName = "\0mctp-pcie-mux"s;
                break;
            case TransportMedium::SPI:
                sockName = "\0mctp-spi-mux"s;
                break;
            case TransportMedium::I2C:
                sockName = "\0mctp-i2c"s + std::to_string(m_i2c_bus_no) + "-mux"s;
                break;
        }
        if (!mctpIO.createSocket(sockName))
        {
            throw std::logic_error(
                "Unable connect to MCTP socket "s + sockName.substr(1)
            );
        }
    }
    // Recv data over MCTP with timeout
    auto SpdmTool::recvMctp(std::vector<uint8_t>& buf) -> spdmcpp::RetStat
    {
        static constexpr auto timeout = 15000U;
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
        log.print("sendBufer.size() = ");
        log.println(buf.size());
        log.print("sendBufer = ");
        log.println(buf);
        return mctpIO.write(buf);
    }

}
