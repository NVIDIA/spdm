
#include "common.hpp"

#include <sdeventplus/event.hpp>
#include <spdmcpp/mctp_support.hpp>

struct ProgramOptions
{
    bool Verbose = false;
    uint16_t PortNumber = 2323;
    SocketTransportTypeEnum TransportType =
        SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_MCTP;
    uint8_t EID = 0;

    int parse(int argc, char** argv)
    {
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays) TODO use CLI11
        static struct option longOptions[] = {
            {"verbose", required_argument, nullptr, 'v'},
            {"trans", required_argument, nullptr, 't'},
            {"eid", required_argument, nullptr, 'e'},
            {"port", required_argument, nullptr, 'p'},
            {nullptr, 0, nullptr, 0}};

        for (;;)
        {
            // NOLINTNEXTLINE cppcoreguidelines-pro-bounds-array-to-pointer-decay
            auto argflag = getopt_long(argc, argv, "v:", longOptions, nullptr);

            if (argflag == -1)
            {
                break;
            }

            switch (argflag)
            {
                case 't':
                    if (strcmp(optarg, "NONE") == 0)
                    {
                        TransportType =
                            SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_NONE;
                    }
                    else if (strcmp(optarg, "MCTP") == 0)
                    {
                        TransportType =
                            SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_MCTP;
                    }
                    else if (strcmp(optarg, "MCTP_DEMUX") == 0)
                    {
                        TransportType = SocketTransportTypeEnum::
                            SOCKET_TRANSPORT_TYPE_MCTP_DEMUX;
                    }
                    else
                    {
                        printUsage();
                        return EX_USAGE;
                    }
                    break;
                case 'e':
                    // NOLINTNEXTLINE(cert-err34-c) TODO use CLI11
                    EID = std::stoi(optarg);
                    break;
                case 'p':
                    // NOLINTNEXTLINE(cert-err34-c) TODO use CLI11
                    PortNumber = std::stoi(optarg);
                    break;
                case 'v':
                    switch (std::stoi(optarg))
                    {
                        case 0:
                            Verbose = false;
                            break;
                        case 1:
                            Verbose = true;
                            break;
                        default:
                            printUsage();
                            return EX_USAGE;
                    }
                    break;
                default:
                    printUsage();
                    return EX_USAGE;
            }
        }
        return 0;
    }

    static void printUsage(void)
    {
        std::cerr << "Usage: spdmcpp_emu_requester [options]\n";
        std::cerr << "Options:\n";
        std::cerr << "  --trans <NONE, MCTP, MCTP_DEMUX>\n";
        std::cerr
            << "           NONE and MCTP connect to a socket created by an spdm_responder_emu with a matching --trans parameter\n";
        std::cerr
            << "           MCTP_DEMUX connects to a socket created by an mctp-demux-daemon and sends packets to the endpoint specified with --eid\n";
        std::cerr
            << "  --eid <MCTP/SPDM Endpoint ID to connect with when using --trans MCTP_DEMUX>\n";
        std::cerr
            << "  --port <Port to connect with when using --trans NONE/MCTP>\n";
        std::cerr
            << "  --verbose <0 - Disable verbosity, 1 - Enable verbosity>\n";
        std::cerr << "Default settings:  --verbose=0 \n";
        // TODO more automatic...
    }
};

class EmulatorClient : public EmulatorBase
{
  public:
    bool routine(ProgramOptions& opt)
    {
        spdmcpp::LogClass log(std::cout);
        TransportType = opt.TransportType;

        int ioSocket = -1;
        SPDMCPP_ASSERT(!Transport);
        switch (TransportType)
        {
            case SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_MCTP:
                if (!connect(opt.PortNumber))
                {
                    return false;
                }
                ioSocket = Socket;
                IO = new EMUIOClass(*this);
                Transport = new spdmcpp::EmuMctpTransportClass;
                break;
            case SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_PCI_DOE:
                SPDMCPP_ASSERT(false);
                //	spdm_registerTransport_layer_func(spdm_context,
                // spdm_transport_pci_doe_encode_message,
                // spdm_transport_pci_doe_decode_message);
                break;
            case SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_NONE:
                if (!connect(opt.PortNumber))
                {
                    return false;
                }
                ioSocket = Socket;
                IO = new EMUIOClass(*this);
                // TODO FIX Transport is now required
                break;
            case SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_MCTP_DEMUX:
                {
                    auto io = new spdmcpp::MctpIoClass(log);
                    if (!io->createSocket()) {
                        delete io;
                        return false;
                    }
                    ioSocket = io->getSocket();
                    IO = io;
                }
                Transport = new spdmcpp::MctpTransportClass(opt.EID);
                break;
            default:
                SPDMCPP_ASSERT(false);
                deleteSpdmcpp();
                return false;
        }

        if (!createSpdmcpp())
        {
            return false;
        }

        spdmcpp::ConnectionClass con(*Context, log);

        if (Transport)
        {
            con.registerTransport(*Transport);
        }

        auto callback = [this, &con](sdeventplus::source::IO& /*io*/,
                                     int /*fd*/, uint32_t revents) {
            // 			spdmcpp::LogClass& log = con.getLog();
            // 			log.iprintln("Event recv!");

            if (!(revents & EPOLLIN))
            {
                return;
            }

            std::vector<uint8_t>& buf = con.getResponseBufferRef();

            IO->read(buf);
            // 			log.iprint("Event recv buf: ");
            // 			log.println(buf.data(), buf.size());
            (void)con.handleRecv();
            if (!con.isWaitingForResponse())
            {
                event.exit(0);
            }
        };

        sdeventplus::source::IO io(event, ioSocket, EPOLLIN, std::move(callback));

        if (TransportType ==
                SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_MCTP ||
            TransportType ==
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

        auto rs = con.refreshMeasurements(0);
        SPDMCPP_LOG_TRACE_RS(con.getLog(), rs);

        std::cout << "press enter to continue...\n";
        event.loop();

        if (Transport)
        {
            con.unregisterTransport(*Transport);
            delete Transport;
            Transport = nullptr;
        }
        deleteSpdmcpp();
        return true;
    }

  private:
    bool connect(uint16_t port)
    {
        switch (TransportType)
        {
            case SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_MCTP:
            case SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_PCI_DOE:
            case SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_NONE:
            {
                if (!createSocket())
                {
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
                if (::connect(Socket, (struct sockaddr*)&serverAddr,
                              sizeof(serverAddr)) == -1)
                {
                    std::cerr << "connect() error: " << errno << " "
                              << strerror(errno) << " to port: '" << port
                              << "'; spdm_responder_emu not running?"
                              << std::endl;
                    close(Socket);
                    Socket = -1;
                    return false;
                }
                std::cout << "Connect success!\n";
                break;
            }
            default:
                SPDMCPP_ASSERT(false);
                return false;
        }
        return true;
    }
};

int main(int argc, char** argv)
{
    ProgramOptions opt;

    if (int ret = opt.parse(argc, argv))
    {
        return ret;
    }

    EmulatorClient emu;
    if (!emu.routine(opt))
    {
        return -1;
    }
    return 0;
}
