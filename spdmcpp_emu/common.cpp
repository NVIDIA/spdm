
#include <common.hpp>
#include <spdmcpp/context.hpp>

#include <sdeventplus/source/time.hpp>

EmulatorIOClass::EmulatorIOClass(SocketTransportTypeEnum trans) : transportType(trans)
{
}

EmulatorIOClass::~EmulatorIOClass()
{
    if (socket != -1)
    {
        deleteSocket();
    }
}

bool EmulatorIOClass::createSocket(uint16_t port)
{
    SPDMCPP_ASSERT(socket == -1);
    socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket == -1)
    {
        std::cerr << "Create socket error: " << errno << std::endl;
        return false;
    }

    struct in_addr mIpAddress = {0x0100007F}; // TODO option?
    struct sockaddr_in serverAddr
    {};
    serverAddr.sin_family = AF_INET;
    memcpy(&serverAddr.sin_addr.s_addr, &mIpAddress,
            sizeof(struct in_addr));
    // NOLINTNEXTLINE cppcoreguidelines-pro-bounds-array-to-pointer-decay
    serverAddr.sin_port = htons(port);
    // NOLINTNEXTLINE cppcoreguidelines-pro-bounds-array-to-pointer-decay
    memset(serverAddr.sin_zero, 0, sizeof(serverAddr.sin_zero));

    // NOLINTNEXTLINE cppcoreguidelines-pro-type-cstyle-cast
    if (::connect(socket, (struct sockaddr*)&serverAddr,
                    sizeof(serverAddr)) == -1)
    {
        std::cerr << "connect() error: " << errno << " "
                    << strerror(errno) << " to port: '" << port
                    << "'; spdm_responder_emu not running?"
                    << std::endl;
        close(socket);
        socket = -1;
        return false;
    }
    std::cout << "Connect success!\n";
    if (transportType ==
            SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_MCTP ||
        transportType ==
            SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_PCI_DOE)
    {
        BufferType msg("Client Hello!");
        auto response = SocketCommandEnum::SOCKET_SPDM_COMMAND_UNKOWN;
        BufferType recv;
        if (!sendMessageReceiveResponse(
                SocketCommandEnum::SOCKET_SPDM_COMMAND_TEST, msg, response,
                recv))
        {
            return false;
        }
        SPDMCPP_ASSERT(response ==
                        SocketCommandEnum::SOCKET_SPDM_COMMAND_TEST);
        std::cout << "Got back: " << recv.data() << std::endl;
    }

    return true;
}

void EmulatorIOClass::deleteSocket()
{
    close(socket);
    socket = -1;
}

bool EmulatorIOClass::writeBytes(const uint8_t* buf, size_t size)
{
    size_t sent = 0;
    while (sent < size)
    {
        // NOLINTNEXTLINE cppcoreguidelines-pro-bounds-pointer-arithmetic
        ssize_t ret = send(socket, (void*)(buf + sent), size - sent, 0);
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
bool EmulatorIOClass::readBytes(uint8_t* buf, size_t size)
{
    size_t done = 0;
    while (done < size)
    {
        // NOLINTNEXTLINE cppcoreguidelines-pro-bounds-pointer-arithmetic
        ssize_t result = recv(socket, (void*)(buf + done), size - done, 0);
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

bool EmulatorIOClass::writeBytes(const std::vector<uint8_t>& buf)
{
    return writeBytes(buf.data(), buf.size());
}
bool EmulatorIOClass::readBytes(std::vector<uint8_t>& buf)
{
    return readBytes(buf.data(), buf.size());
}

bool EmulatorIOClass::writeData32(uint32_t data)
{
    data = htonl(data);
    // NOLINTNEXTLINE cppcoreguidelines-pro-type-cstyle-cast
    return writeBytes((uint8_t*)&data, sizeof(data));
}
bool EmulatorIOClass::readData32(uint32_t* data)
{
    // NOLINTNEXTLINE cppcoreguidelines-pro-type-cstyle-cast
    if (!readBytes((uint8_t*)data, sizeof(*data)))
    {
        return false;
    }
    *data = ntohl(*data);
    return true;
}

bool EmulatorIOClass::writeData(SocketCommandEnum cmd)
{
    return writeData32(static_cast<uint32_t>(cmd));
}
bool EmulatorIOClass::readData(SocketCommandEnum& cmd)
{
    uint32_t data = 0;
    if (!readData32(&data))
    {
        return false;
    }
    cmd = static_cast<SocketCommandEnum>(data);
    return true;
}

bool EmulatorIOClass::sendBuf(const std::vector<uint8_t>& buf)
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

bool EmulatorIOClass::receiveBuf(std::vector<uint8_t>& buf)
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

bool EmulatorIOClass::sendPlatformData(SocketCommandEnum command,
                        const std::vector<uint8_t>& buf)
{
    if (!writeData(command))
    {
        return false;
    }
    if (!writeData32(static_cast<uint32_t>(transportType)))
    {
        return false;
    }
    if (!sendBuf(buf))
    {
        return false;
    }

    return true;
}

bool EmulatorIOClass::receivePlatformData(SocketCommandEnum& command,
                            std::vector<uint8_t>& recv)
{
    if (!readData(command))
    {
        return false;
    }
    {
        uint32_t trans = 0;
        if (!readData32(&trans))
        {
            return false;
        }
        SPDMCPP_ASSERT(static_cast<SocketTransportTypeEnum>(
                            trans) == transportType);
    }
    if (!receiveBuf(recv))
    {
        return false;
    }
    return true;
}

bool EmulatorIOClass::sendMessageReceiveResponse(SocketCommandEnum command,
                                const BufferType& send,
                                SocketCommandEnum& response,
                                BufferType& recv)
{
    if (!sendPlatformData(command, send))
    {
        std::cerr << "sendPlatformData error: " << errno << std::endl;
        return false;
    }
    if (!receivePlatformData(response, recv))
    {
        std::cerr << "receivePlatformData error: " << errno << std::endl;
        return false;
    }
    return true;
}

spdmcpp::RetStat EmulatorIOClass::write(const std::vector<uint8_t>& buf,
                                   spdmcpp::timeout_us_t /*timeout*/)
{
    if (!sendPlatformData(SocketCommandEnum::SOCKET_SPDM_COMMAND_NORMAL, buf))
    {
        return spdmcpp::RetStat::ERROR_UNKNOWN;
    }
    return spdmcpp::RetStat::OK;
}

spdmcpp::RetStat EmulatorIOClass::read(std::vector<uint8_t>& buf,
                                  spdmcpp::timeout_us_t /*timeout*/)
{
    auto response = SocketCommandEnum::SOCKET_SPDM_COMMAND_UNKOWN;
    if (!receivePlatformData(response, buf))
    {
        return spdmcpp::RetStat::ERROR_UNKNOWN;
    }
    SPDMCPP_ASSERT(response == SocketCommandEnum::SOCKET_SPDM_COMMAND_NORMAL);
    return spdmcpp::RetStat::OK;
}

