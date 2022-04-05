
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
#include <spdmcpp/context.hpp>
#include <spdmcpp/connection.hpp>

namespace spdmcpp
{
class EmuMctpTransportClass :
    public TransportClass // for matching dmtf spdm emulator --trans MCTP
{
  public:
    RetStat encodePre(std::vector<uint8_t>& /*buf*/, LayerState& lay) override
    {
        setLayerSize(lay, sizeof(HeaderType));
        return spdmcpp::RetStat::OK;
    }
    RetStat encodePost(std::vector<uint8_t>& buf, LayerState& lay) override
    {
        auto& header = getHeaderRef<HeaderType>(buf, lay);
        header.MessageType = MCTPMessageTypeEnum::SPDM;
        return RetStat::OK;
    }

    RetStat decode(std::vector<uint8_t>& /*buf*/, LayerState& lay) override
    {
        setLayerSize(lay, sizeof(HeaderType));
        return spdmcpp::RetStat::OK;
    }

  protected:
    struct HeaderType
    {
        MCTPMessageTypeEnum MessageType;
    };
};
} // namespace spdmcpp

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

    BufferType(const char* str)
    {
        size_t s = strlen(str) + 1;
        resize(s);
        memcpy(data(), str, s);
    }
};

class EmulatorBase;

class EMUIOClass : public spdmcpp::IOClass
{
  public:
    EMUIOClass(EmulatorBase& emu);

    spdmcpp::RetStat write(
        const std::vector<uint8_t>& buf,
        spdmcpp::timeout_us_t timeout = spdmcpp::TIMEOUT_US_INFINITE) override;
    spdmcpp::RetStat read(
        std::vector<uint8_t>& buf,
        spdmcpp::timeout_us_t timeout = spdmcpp::TIMEOUT_US_INFINITE) override;
    spdmcpp::RetStat setupTimeout(spdmcpp::timeout_us_t timeout) override;

  private:
    EmulatorBase& Emulator;
};

class DemuxIOClass :
    public spdmcpp::IOClass // TODO decouple from EmulatorBase and generalize
{
  public:
    DemuxIOClass(EmulatorBase& emu);

    spdmcpp::RetStat write(
        const std::vector<uint8_t>& buf,
        spdmcpp::timeout_us_t timeout = spdmcpp::TIMEOUT_US_INFINITE) override;
    spdmcpp::RetStat read(
        std::vector<uint8_t>& buf,
        spdmcpp::timeout_us_t timeout = spdmcpp::TIMEOUT_US_INFINITE) override;
    spdmcpp::RetStat setupTimeout(spdmcpp::timeout_us_t timeout) override;

  private:
    EmulatorBase& Emulator;
};

//NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class EmulatorBase : public spdmcpp::NonCopyable
{
    friend EMUIOClass;
    friend DemuxIOClass;

  public:
    EmulatorBase() : Event(sdeventplus::Event::get_default())
    {}
    EmulatorBase(int socket) :
        Socket(socket), Event(sdeventplus::Event::get_default())
    {}
    ~EmulatorBase()
    {
        closeSocketIfCreated();
        SPDMCPP_ASSERT(!Context);
    }

    // TODO rename for clearer layer separation and meaning ! and depend more on
    // function type overloading?
    // TODO move functions to .cpp
    bool writeBytes(const uint8_t* buf, size_t size)
    {
        size_t sent = 0;
        while (sent < size)
        {
            ssize_t ret = send(Socket, (void*)(buf + sent), size - sent, 0);
            if (ret == -1)
            {
                std::cerr << "EmulatorBase::write_bytes() errno = " << errno
                          << std::endl;
                return false;
            }
            sent += ret;
        }
        return true;
    }
    bool readBytes(uint8_t* buf, size_t size)
    {
        size_t done = 0;
        while (done < size)
        {
            ssize_t result = recv(Socket, (void*)(buf + done), size - done, 0);
            if (result == -1)
            {
                std::cerr << "EmulatorBase::read_bytes() errno = " << errno
                          << std::endl;
                return false;
            }
            if (result == 0)
            {
                return false;
            }
            done += result;
        }
        return true;
    }

    bool writeBytes(const std::vector<uint8_t>& buf)
    {
        return writeBytes(buf.data(), buf.size());
    }
    bool readBytes(std::vector<uint8_t>& buf)
    {
        return readBytes(buf.data(), buf.size());
    }

    bool writeData32(uint32_t data)
    {
        data = htonl(data);
        return writeBytes((uint8_t*)&data, sizeof(data));
    }
    bool readData32(uint32_t* data)
    {
        if (!readBytes((uint8_t*)data, sizeof(*data)))
        {
            return false;
        }
        *data = ntohl(*data);
        return true;
    }

    bool writeData(SocketCommandEnum cmd)
    {
        return writeData32(static_cast<uint32_t>(cmd));
    }
    bool readData(SocketCommandEnum& cmd)
    {
        uint32_t data = 0;
        if (!readData32(&data))
        {
            return false;
        }
        cmd = static_cast<SocketCommandEnum>(data);
        return true;
    }

    bool sendBuf(const std::vector<uint8_t>& buf)
    {
        if (!writeData32(buf.size()))
        {
            return false;
        }
        if (!writeBytes(buf))
        {
            return false;
        }
        return true;
    }

    bool receiveBuf(std::vector<uint8_t>& buf)
    {
        uint32_t size = 0;
        if (!readData32(&size))
        {
            return false;
        }
        buf.resize(size);
        if (!readBytes(buf))
        {
            return false;
        }
        return true;
    }

    bool sendPlatformData(SocketCommandEnum command,
                          const std::vector<uint8_t>& buf)
    {
        if (!writeData(command))
        {
            return false;
        }
        if (!writeData32(static_cast<uint32_t>(TransportType)))
        {
            return false;
        }
        if (!sendBuf(buf))
        {
            return false;
        }

        return true;
    }

    bool receivePlatformData(SocketCommandEnum& command,
                             std::vector<uint8_t>& recv)
    {
        if (!readData(command))
        {
            return false;
        }
        {
            uint32_t transportType = 0;
            if (!readData32(&transportType))
            {
                return false;
            }
            SPDMCPP_ASSERT(static_cast<SocketTransportTypeEnum>(transportType) ==
                   TransportType);
        }
        if (!receiveBuf(recv))
        {
            return false;
        }
        return true;
    }

    bool sendMessageReceiveResponse(SocketCommandEnum command,
                                    const BufferType& send,
                                    SocketCommandEnum& response,
                                    BufferType& recv)
    {
        if (!sendPlatformData(command, send))
        {
            std::cerr<< "sendPlatformData error: " << errno << std::endl;
            return false;
        }
        if (!receivePlatformData(response, recv))
        {
            std::cerr<< "receivePlatformData error: " << errno << std::endl;
            return false;
        }
        return true;
    }

  protected:
    int Socket = -1;
    spdmcpp::ContextClass* Context = nullptr;

    spdmcpp::IOClass* IO = nullptr;

    SocketTransportTypeEnum TransportType =
        SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_UNKNOWN;
    spdmcpp::TransportClass* Transport = nullptr;

    sdeventplus::Event Event;
    sdeventplus::source::Time<sdeventplus::ClockId::Monotonic>* Timeout =
        nullptr;

    bool createSocket()
    {
        SPDMCPP_ASSERT(Socket == -1);
        Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (Socket == -1)
        {
            std::cerr<< "Create Socket error: " << errno << std::endl;
            return false;
        }
        return true;
    }
    void closeSocket()
    {
        SPDMCPP_ASSERT(Socket != -1);
        close(Socket);
        Socket = -1;
    }
    void closeSocketIfCreated()
    {
        if (Socket != -1)
        {
            closeSocket();
        }
    }

    bool createSpdmcpp()
    {
        Context = new spdmcpp::ContextClass;
        Context->registerIo(IO);
        return true;
    }
    void deleteSpdmcpp()
    {
        Context->unregisterIo(IO);
        delete IO;
        delete Context;
        Context = nullptr;
    }
};
