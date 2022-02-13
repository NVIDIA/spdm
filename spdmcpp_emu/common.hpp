
#pragma once

#include <arpa/inet.h>
#include <err.h>
#include <getopt.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sysexits.h>
#include <unistd.h>

#include <sdeventplus/event.hpp>

#include <cstdio>
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
#include <spdmcpp/common.hpp>

namespace spdmcpp
{
class EMU_MCTP_TransportClass :
    public TransportClass // for matching dmtf spdm emulator --trans MCTP
{
  public:
    virtual ~EMU_MCTP_TransportClass()
    {}

    virtual RetStat encode_pre(std::vector<uint8_t>& /*buf*/, LayerState& lay)
    {
        set_layer_size(lay, sizeof(header_type));
        return spdmcpp::RetStat::OK;
    }
    virtual RetStat encode_post(std::vector<uint8_t>& buf, LayerState& lay)
    {
        auto& header = get_header_ref<header_type>(buf, lay);
        header.MessageType = MCTPMessageTypeEnum::SPDM;
        return RetStat::OK;
    }

    virtual RetStat decode(std::vector<uint8_t>& /*buf*/, LayerState& lay)
    {
        set_layer_size(lay, sizeof(header_type));
        return spdmcpp::RetStat::OK;
    }

  protected:
    struct header_type
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

struct buffer_t : public std::vector<uint8_t>
{
    // TODO add custom helpers for appending, presetting headers, etc?
    buffer_t()
    {}

    buffer_t(const char* str)
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

    ~EMUIOClass() override;
    spdmcpp::RetStat write(
        const std::vector<uint8_t>& buf,
        spdmcpp::timeout_us_t timeout = spdmcpp::TIMEOUT_US_INFINITE) override;
    spdmcpp::RetStat read(
        std::vector<uint8_t>& buf,
        spdmcpp::timeout_us_t timeout = spdmcpp::TIMEOUT_US_INFINITE) override;
    spdmcpp::RetStat setup_timeout(spdmcpp::timeout_us_t timeout) override;

  private:
    EmulatorBase& Emulator;
};

class DemuxIOClass :
    public spdmcpp::IOClass // TODO decouple from EmulatorBase and generalize
{
  public:
    DemuxIOClass(EmulatorBase& emu);

    ~DemuxIOClass() override;
    spdmcpp::RetStat write(
        const std::vector<uint8_t>& buf,
        spdmcpp::timeout_us_t timeout = spdmcpp::TIMEOUT_US_INFINITE) override;
    spdmcpp::RetStat read(
        std::vector<uint8_t>& buf,
        spdmcpp::timeout_us_t timeout = spdmcpp::TIMEOUT_US_INFINITE) override;
    spdmcpp::RetStat setup_timeout(spdmcpp::timeout_us_t timeout) override;

  private:
    EmulatorBase& Emulator;
};

class EmulatorBase
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
        close_socket_if_created();
        assert(!Context);
    }

    // TODO rename for clearer layer separation and meaning ! and depend more on
    // function type overloading?
    // TODO move functions to .cpp
    bool write_bytes(const uint8_t* buf, size_t size)
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
    bool read_bytes(uint8_t* buf, size_t size)
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

    bool write_bytes(const std::vector<uint8_t>& buf)
    {
        return write_bytes(buf.data(), buf.size());
    }
    bool read_bytes(std::vector<uint8_t>& buf)
    {
        return read_bytes(buf.data(), buf.size());
    }

    bool write_data32(uint32_t data)
    {
        data = htonl(data);
        return write_bytes((uint8_t*)&data, sizeof(data));
    }
    bool read_data32(uint32_t* data)
    {
        if (!read_bytes((uint8_t*)data, sizeof(*data)))
        {
            return false;
        }
        *data = ntohl(*data);
        return true;
    }

    bool write_data(SocketCommandEnum cmd)
    {
        return write_data32(static_cast<uint32_t>(cmd));
    }
    bool read_data(SocketCommandEnum& cmd)
    {
        uint32_t data;
        if (!read_data32(&data))
        {
            return false;
        }
        cmd = static_cast<SocketCommandEnum>(data);
        return true;
    }

    bool send_buf(const std::vector<uint8_t>& buf)
    {
        if (!write_data32(buf.size()))
        {
            return false;
        }
        if (!write_bytes(buf))
        {
            return false;
        }
        return true;
    }

    bool receive_buf(std::vector<uint8_t>& buf)
    {
        uint32_t size;
        if (!read_data32(&size))
        {
            return false;
        }
        buf.resize(size);
        if (!read_bytes(buf))
        {
            return false;
        }
        return true;
    }

    bool send_platform_data(SocketCommandEnum command,
                            const std::vector<uint8_t>& buf)
    {
        if (!write_data(command))
        {
            return false;
        }
        if (!write_data32(static_cast<uint32_t>(TransportType)))
        {
            return false;
        }
        if (!send_buf(buf))
        {
            return false;
        }

        return true;
    }

    bool receive_platform_data(SocketCommandEnum& command,
                               std::vector<uint8_t>& recv)
    {
        if (!read_data(command))
        {
            return false;
        }
        {
            uint32_t transport_type;
            if (!read_data32(&transport_type))
            {
                return false;
            }
            assert(static_cast<SocketTransportTypeEnum>(transport_type) ==
                   TransportType);
        }
        if (!receive_buf(recv))
        {
            return false;
        }
        return true;
    }

    bool send_message_receive_response(SocketCommandEnum command,
                                       const buffer_t& send,
                                       SocketCommandEnum& response,
                                       buffer_t& recv)
    {
        if (!send_platform_data(command, send))
        {
            printf("send_platform_data Error - %x\n", errno);
            return false;
        }
        if (!receive_platform_data(response, recv))
        {
            printf("receive_platform_data Error - %x\n", errno);
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
    sdeventplus::source::Time<sdeventplus::ClockId::Monotonic>* Timeout;

    bool create_socket()
    {
        assert(Socket == -1);
        Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (Socket == -1)
        {
            printf("Create Socket Failed - %x\n", errno);
            return false;
        }
        return true;
    }
    void close_socket()
    {
        assert(Socket != -1);
        close(Socket);
        Socket = -1;
    }
    void close_socket_if_created()
    {
        if (Socket != -1)
        {
            close_socket();
        }
    }

    bool create_spdmcpp()
    {
        Context = new spdmcpp::ContextClass;
        Context->register_io(IO);
        return true;
    }
    void delete_spdmcpp()
    {
        Context->unregister_io(IO);
        delete IO;
        delete Context;
        Context = nullptr;
    }
};
