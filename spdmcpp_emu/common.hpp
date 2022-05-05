
#pragma once

#include <arpa/inet.h>
#include <err.h>
#include <getopt.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sysexits.h>
#include <unistd.h>

#include <sdeventplus/event.hpp>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
// TODO minimize includes

#include <sdeventplus/source/io.hpp>
#include <sdeventplus/source/time.hpp>
#include <spdmcpp/assert.hpp>
#include <spdmcpp/common.hpp>
#include <spdmcpp/connection.hpp>
#include <spdmcpp/context.hpp>

enum class SocketCommandEnum : uint32_t
{
    SOCKET_SPDM_COMMAND_NORMAL = 0x0001,
    SOCKET_SPDM_COMMAND_OOB_ENCAP_KEY_UPDATE = 0x0001,
    SOCKET_SPDM_COMMAND_CONTINUE = 0xFFFD,
    SOCKET_SPDM_COMMAND_SHUTDOWN = 0xFFFE,
    SOCKET_SPDM_COMMAND_UNKOWN = 0xFFFF,
    SOCKET_SPDM_COMMAND_TEST = 0xDEAD,
};

enum class SocketTransportTypeEnum : uint32_t
{
    SOCKET_TRANSPORT_TYPE_NONE = 0x00,
    SOCKET_TRANSPORT_TYPE_MCTP = 0x01,
    SOCKET_TRANSPORT_TYPE_PCI_DOE = 0x02,
    SOCKET_TRANSPORT_TYPE_MCTP_DEMUX = 0x03,
    SOCKET_TRANSPORT_TYPE_UNKNOWN = 0xFF,
};

struct BufferType : public std::vector<uint8_t>
{
    // TODO add custom helpers for appending, presetting headers, etc?
    BufferType() = default;

    explicit BufferType(const char* str)
    {
        size_t s = strlen(str) + 1;
        resize(s);
        memcpy(data(), str, s);
    }
};

// NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class EmulatorTransportClass :
    public spdmcpp::TransportClass // for matching dmtf spdm emulator --trans
                                   // MCTP
{
  public:
    EmulatorTransportClass() = default;

    template <typename T>
    explicit EmulatorTransportClass(const T& header)
    {
        headerData.resize(sizeof(T));
        memcpy(headerData.data(), &header, sizeof(T));
    }

    spdmcpp::RetStat encodePre(std::vector<uint8_t>& buf,
                               LayerState& lay) override
    {
        setLayerSize(lay, headerData.size());
        if (!headerData.empty())
        {
            buf.resize(lay.getEndOffset());
            auto start = static_cast<std::vector<uint8_t>::difference_type>(
                lay.getOffset());
            std::copy(headerData.begin(), headerData.end(),
                      std::next(buf.begin(), start));
        }
        return spdmcpp::RetStat::OK;
    }
    spdmcpp::RetStat encodePost(std::vector<uint8_t>& /*buf*/,
                                LayerState& /*lay*/) override
    {
        return spdmcpp::RetStat::OK;
    }

    spdmcpp::RetStat decode(std::vector<uint8_t>& /*buf*/,
                            LayerState& lay) override
    {
        setLayerSize(lay, headerData.size());
        return spdmcpp::RetStat::OK;
    }

    spdmcpp::RetStat setupTimeout(spdmcpp::timeout_ms_t /*timeout*/) override
    {
        // pretend it's working fine, we don't actually need it at the moment
        return spdmcpp::RetStat::OK;
    }

  protected:
    std::vector<uint8_t> headerData;
};

// NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class EmulatorIOClass : public spdmcpp::IOClass
{
  public:
    explicit EmulatorIOClass(SocketTransportTypeEnum transport);
    ~EmulatorIOClass() override;

    bool createSocket(uint16_t port);
    void deleteSocket();

    bool writeBytes(const uint8_t* buf, size_t size);
    bool readBytes(uint8_t* buf, size_t size);

    bool writeBytes(const std::vector<uint8_t>& buf);
    bool readBytes(std::vector<uint8_t>& buf);

    bool writeData32(uint32_t data);
    bool readData32(uint32_t* data);

    bool writeData(SocketCommandEnum cmd);
    bool readData(SocketCommandEnum& cmd);

    bool sendBuf(const std::vector<uint8_t>& buf);

    bool receiveBuf(std::vector<uint8_t>& buf);

    bool sendPlatformData(SocketCommandEnum command,
                          const std::vector<uint8_t>& buf);

    bool receivePlatformData(SocketCommandEnum& command,
                             std::vector<uint8_t>& recv);

    bool sendMessageReceiveResponse(SocketCommandEnum command,
                                    const BufferType& send,
                                    SocketCommandEnum& response,
                                    BufferType& recv);

    spdmcpp::RetStat write(
        const std::vector<uint8_t>& buf,
        spdmcpp::timeout_us_t timeout = spdmcpp::TIMEOUT_US_INFINITE) override;
    spdmcpp::RetStat read(
        std::vector<uint8_t>& buf,
        spdmcpp::timeout_us_t timeout = spdmcpp::TIMEOUT_US_INFINITE) override;

    int getSocket() const
    {
        return socket;
    }

  protected:
    // static constexpr sdeventplus::ClockId cid =
    // sdeventplus::ClockId::Monotonic;
    // sdeventplus::source::Time<sdeventplus::ClockId::Monotonic>* timeout =
    // nullptr;
    SocketTransportTypeEnum transportType =
        SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_UNKNOWN;
    int socket = -1;
};

// NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class EmulatorBase : public spdmcpp::NonCopyable
{
  public:
    EmulatorBase() : event(sdeventplus::Event::get_default())
    {}
    ~EmulatorBase()
    {
        SPDMCPP_ASSERT(!Context);
        SPDMCPP_ASSERT(!IO);
    }

    sdeventplus::Event event;

  protected:
    std::unique_ptr<spdmcpp::ContextClass> Context;
    std::unique_ptr<spdmcpp::ConnectionClass> connection;

    std::unique_ptr<spdmcpp::IOClass> IO;
    std::unique_ptr<spdmcpp::TransportClass> Transport;

    bool createContext()
    {
        Context = std::make_unique<spdmcpp::ContextClass>();
        Context->registerIo(*IO);
        return true;
    }
    void deleteContext()
    {
        Context->unregisterIo(*IO);
        IO.reset(nullptr);
        Context.reset(nullptr);
    }
};
