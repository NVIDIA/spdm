#pragma once

#include <spdmcpp/common.hpp>
#include "cmds.hpp"
#include <memory>
#include <vector>
#include <spdmcpp/mctp_support.hpp>
#include <spdmcpp/log.hpp>
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

    private:
        //! Logger
        spdmcpp::LogClass log;
        //! Selected medium
        spdmcpp::TransportMedium medium{spdmcpp::TransportMedium::PCIe};
        //! Current request with args
        std::vector<cmdv> cmdList;
        // Connection class
        spdmcpp::MctpIoClass mctpIO;
        //! Target EID
        int m_eid {};
        //! MCTP transport
        std::unique_ptr<spdmcpp::MctpTransportClass> transport;
        //! Packet decode info
        spdmcpp::PacketDecodeInfo packetDecodeInfo;
    };

    //! Prepare request
    template <typename T>
    auto SpdmTool::prepareRequest(const T& packet, std::vector<uint8_t>& buf)
        -> spdmcpp::RetStat
    {
        using namespace spdmcpp;
        log.iprint("sendRequest(");
        log.print(typeid(packet).name());
        log.println("):");
        packet.printMl(log);
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
        log.iprint("interpretResponse(");
        log.print(typeid(packet).name());
        log.println("):");
        packet.printMl(log);
        return rs;
    }

}