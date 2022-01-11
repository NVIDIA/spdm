
#include "common.hpp"

#include <sdeventplus/event.hpp>

#include "cxxopts.hpp"

#define DEFAULT_SPDM_PLATFORM_PORT 2323

cxxopts::Options options("spdmcpp_emu_requester", "spdmcpp_emu_requester");

struct ProgramOptions
{
	bool Verbose = false;
	uint16_t PortNumber = DEFAULT_SPDM_PLATFORM_PORT;
	SocketTransportTypeEnum TransportType = SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_MCTP;
	uint8_t EID = 0;
	
	int parse(int argc, char** argv)
	{
		static struct option long_options[] = {
			{"verbose", required_argument, nullptr, 'v'},
			{"trans", required_argument, nullptr, 't'},
			{"eid", required_argument, nullptr, 'e'},
			{"port", required_argument, nullptr, 'p'},
			{nullptr, 0, nullptr, 0}
		};
		
		for (;;) {
			auto argflag = getopt_long(argc, argv, "v:", long_options, nullptr);

			if (argflag == -1)
				break;

			switch (argflag)
			{
			case 't':
				if (strcmp(optarg, "NONE") == 0) {
					TransportType = SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_NONE;
				}
				else if (strcmp(optarg, "MCTP") == 0) {
					TransportType = SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_MCTP;
				}
				else if (strcmp(optarg, "MCTP_DEMUX") == 0) {
					TransportType = SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_MCTP_DEMUX;
				}
				else {
					print_usage();
					return EX_USAGE;
				}
				break;
			case 'e':
				EID = atoi(optarg);
				break;
			case 'p':
				PortNumber = atoi(optarg);
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
					print_usage();
					return EX_USAGE;
				}
				break;
			default:
				print_usage();
				return EX_USAGE;
			}
		}
		return 0;
	}

	
	static void print_usage(void)
	{
		std::cerr << "Usage: spdmcpp_emu_requester [options]\n";
		std::cerr << "Options:\n";
		std::cerr << "  --trans <NONE, MCTP, MCTP_DEMUX>\n";
		std::cerr << "           NONE and MCTP connect to a socket created by an spdm_responder_emu with a matching --trans parameter\n";
		std::cerr << "           MCTP_DEMUX connects to a socket created by an mctp-demux-daemon and sends packets to the endpoint specified with --eid\n";
		std::cerr << "  --eid <MCTP/SPDM Endpoint ID to connect with when using --trans MCTP_DEMUX>\n";
		std::cerr << "  --port <Port to connect with when using --trans NONE/MCTP>\n";
		std::cerr << "  --verbose <0 - Disable verbosity, 1 - Enable verbosity>\n";
		std::cerr << "Default settings:  --verbose=0 \n";
		//TODO more automatic...
	}	
};


class EmulatorClient : public EmulatorBase
{
public:
	bool routine(ProgramOptions& opt)
	{
		TransportType = opt.TransportType;
		
		assert(!Transport);
		switch (TransportType) {
		case SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_MCTP:
			IO = new EMUIOClass(*this);
			Transport = new spdmcpp::EMU_MCTP_TransportClass;
			break;
		case SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_PCI_DOE:
			assert(false);
		//	spdm_register_transport_layer_func(spdm_context, spdm_transport_pci_doe_encode_message, spdm_transport_pci_doe_decode_message);
			break;
		case SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_NONE:
			IO = new EMUIOClass(*this);
			break;
		case SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_MCTP_DEMUX:
			IO = new DemuxIOClass(*this);
			Transport = new spdmcpp::MCTP_TransportClass(opt.EID);
			break;
		default:
			assert(false);
			delete_spdmcpp();
			return false;
		}
		
		if (!connect(opt.PortNumber)) {
			return false;
		}
		
		if (!create_spdmcpp()) {
			return false;
		}
		
		spdmcpp::ConnectionClass con(Context);
		
		auto callback = [this, &con](sdeventplus::source::IO& /*io*/, int /*fd*/, uint32_t revents)
		{
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
			spdmcpp::EventRetStat rs = con.handle_recv();
			if (rs == spdmcpp::EventRetStat::ERROR_EXIT) {
				Event.exit(0);
			}
		};
		
		sdeventplus::source::IO io(Event, Socket, EPOLLIN, std::move(callback));
		
		constexpr sdeventplus::ClockId cid = sdeventplus::ClockId::Monotonic;
		auto time_cb = [this, &con](sdeventplus::source::Time<cid>& /*source*/, sdeventplus::source::Time<cid>::TimePoint /*time*/)
		{
// 			std::cerr << "IOClass::setup_timeout callback" << std::endl;
			spdmcpp::EventRetStat rs = con.handle_timeout();
			if (rs == spdmcpp::EventRetStat::ERROR_EXIT) {
				Event.exit(0);
			}
		};
		
// 		std::cerr << "IOClass::setup_timeout queue" << std::endl;
		Timeout = new sdeventplus::source::Time<cid>(Event, sdeventplus::Clock<cid>(Event).now(), std::chrono::milliseconds{1}, std::move(time_cb));
		Timeout->set_enabled(sdeventplus::source::Enabled::Off);

		
		if (TransportType == SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_MCTP || TransportType == SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_PCI_DOE) {
			buffer_t msg("Client Hello!");
			SocketCommandEnum response;
			buffer_t recv;
			if (!send_message_receive_response(SocketCommandEnum::SOCKET_SPDM_COMMAND_TEST, msg,
					response, recv))
			{
				return false;
			}
			assert(response == SocketCommandEnum::SOCKET_SPDM_COMMAND_TEST);
			printf("Got back: '%s'\n", recv.data());
		}
	#if 1
		auto rs = con.init_connection();
		SPDMCPP_LOG_TRACE_RS(con.getLog(), rs);
	#else
		auto cb_in = [&con](sdeventplus::source::IO& /*io*/, int fd, uint32_t revents)
		{
			std::cerr << "cb_in\n";
			
			if (!(revents & EPOLLIN)) {
				return;
			}
			std::vector<uint8_t> buf;
			buf.resize(1024);
// 			int returnCode = 0;
			ssize_t peekedLength = read(fd, buf.data(), buf.size());
			if (peekedLength > 0) {
				auto rs = con.init_connection();
				SPDMCPP_LOG_TRACE_RS(con.getLog(), rs);
			}
		};
		sdeventplus::source::IO io2(event, 0, EPOLLIN, std::move(cb_in));
	#endif
		
		std::cout << "press enter to continue...\n";
		Event.loop();
		
		delete_spdmcpp();
		return true;
	}

private:
	
	bool connect(uint16_t port)
	{
		switch (TransportType) {
		case SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_MCTP:
		case SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_PCI_DOE:
		case SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_NONE:
		{
			if (!create_socket()) {
				return false;
			}
			struct in_addr m_ip_address = { 0x0100007F };	//TODO option?
			struct sockaddr_in server_addr;
			server_addr.sin_family = AF_INET;
			memcpy(&server_addr.sin_addr.s_addr, &m_ip_address, sizeof(struct in_addr));
			server_addr.sin_port = htons(port);
			memset(server_addr.sin_zero, 0, sizeof(server_addr.sin_zero));

			if (::connect(Socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
				std::cerr << "connect() error: " << errno << " " << strerror(errno) << " to port: '" << port << "'; spdm_responder_emu not running?" << std::endl;
				close(Socket);
				Socket = -1;
				return false;
			}
			printf("connect success!\n");
			break;
		}
		case SocketTransportTypeEnum::SOCKET_TRANSPORT_TYPE_MCTP_DEMUX:
		{
			Socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
			if (Socket == -1) {
				printf("Create Socket Failed - %x\n", errno);
				return false;
			}
			
			const char path[] = "\0mctp-mux";
			struct sockaddr_un addr;
			addr.sun_family = AF_UNIX;
			memcpy(addr.sun_path, path, sizeof(path) - 1);
			
			if (::connect(Socket, (struct sockaddr *)&addr, sizeof(path) + sizeof(addr.sun_family) - 1) == -1) {
				std::cerr << "connect() error: " << errno << " " << strerror(errno) << " to mctp-demux-daemon; maybe it's not running?" << std::endl;
				close(Socket);
				Socket = -1;
				return false;
			}
			{
				auto type = spdmcpp::MCTPMessageTypeEnum::SPDM;
				ssize_t ret = write(Socket, &type, sizeof(type));
				if (ret == -1) {
					std::cerr << "Failed to write spdm code to socket, errno = " << -errno << "\n";
					return false;
				}
			}
			printf("connect success!\n");
			break;
		}
		default:
			assert(false);
			return false;
		}
		return true;
	}
	
};


int main(int argc, char** argv)
{
	ProgramOptions opt;
	
	if (int ret = opt.parse(argc, argv)) {
		return ret;
	}
	
	EmulatorClient emu;
	if (!emu.routine(opt)) {
		return -1;
	}
	return 0;
}


