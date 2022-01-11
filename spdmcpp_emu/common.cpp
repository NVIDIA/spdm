
#include <common.hpp>

// #include <sdeventplus/utility/timer.hpp>
#include <sdeventplus/source/time.hpp>

EMUIOClass::EMUIOClass(EmulatorBase& emu) : Emulator(emu)
{
}

EMUIOClass::~EMUIOClass()
{
	
}

spdmcpp::RetStat EMUIOClass::write(const std::vector<uint8_t>& buf, spdmcpp::timeout_us_t /*timeout*/)
{
	if (!Emulator.send_platform_data(SocketCommandEnum::SOCKET_SPDM_COMMAND_NORMAL, buf)) {
		return spdmcpp::RetStat::ERROR_UNKNOWN;
	}
	return spdmcpp::RetStat::OK;
}
spdmcpp::RetStat EMUIOClass::read(std::vector<uint8_t>& buf, spdmcpp::timeout_us_t /*timeout*/)
{
	SocketCommandEnum response;
	if (!Emulator.receive_platform_data(response, buf)) {
		return spdmcpp::RetStat::ERROR_UNKNOWN;
	}
	assert(response == SocketCommandEnum::SOCKET_SPDM_COMMAND_NORMAL);
	return spdmcpp::RetStat::OK;
}
spdmcpp::RetStat EMUIOClass::setup_timeout(spdmcpp::timeout_us_t timeout)
{
	constexpr sdeventplus::ClockId cid = sdeventplus::ClockId::Monotonic;
	Emulator.Timeout->set_time(sdeventplus::Clock<cid>(Emulator.Event).now() + std::chrono::microseconds{timeout});
	Emulator.Timeout->set_enabled(sdeventplus::source::Enabled::OneShot);
#if 0
	constexpr sdeventplus::ClockId cid = sdeventplus::ClockId::Monotonic;
// 	using sdeventplus::source::Time<cid>;
	auto callback = [this](sdeventplus::source::Time<cid>& /*source*/, sdeventplus::source::Time<cid>::TimePoint /*time*/)
	{
		std::cerr << "DemuxIOClass::setup_timeout callback" << std::endl;
// 		assert(false);
	};
	
	std::cerr << "DemuxIOClass::setup_timeout queue" << std::endl;
//	sdeventplus::source::Time<cid> time(Emulator.Event, sdeventplus::Clock<cid>(Emulator.Event).now() + std::chrono::microseconds{10}, std::chrono::milliseconds{1}, std::move(callback));
	new sdeventplus::source::Time<cid>(Emulator.Event, sdeventplus::Clock<cid>(Emulator.Event).now() + std::chrono::milliseconds{1000}, std::chrono::milliseconds{1}, std::move(callback));
#endif
	return spdmcpp::RetStat::OK;
}



DemuxIOClass::DemuxIOClass(EmulatorBase& emu) : Emulator(emu)
{
}

DemuxIOClass::~DemuxIOClass()
{
	
}

spdmcpp::RetStat DemuxIOClass::write(const std::vector<uint8_t>& buf, spdmcpp::timeout_us_t /*timeout*/)
{
	size_t sent = 0;
	while (sent < buf.size()) {
		ssize_t ret = send(Emulator.Socket, (void*)(buf.data() + sent), buf.size() - sent, 0);
		if (ret == -1) {
			printf("Send error - 0x%x\n", errno);	//TODO CLEANUP
			return spdmcpp::RetStat::ERROR_UNKNOWN;
		}
		sent += ret;
	}
	return spdmcpp::RetStat::OK;
}
spdmcpp::RetStat DemuxIOClass::read(std::vector<uint8_t>& buf, spdmcpp::timeout_us_t /*timeout*/)
{
	buf.resize(4096);//MCTP_MAX_MSG
	ssize_t result = recv(Emulator.Socket, (void*)buf.data(), buf.size(), 0);
	if (result == -1) {
		buf.clear();
		printf("Receive error - 0x%x\n", errno);	//TODO CLEANUP
		return spdmcpp::RetStat::ERROR_UNKNOWN;
	}
	if (result == 0) {
		buf.clear();
		return spdmcpp::RetStat::ERROR_UNKNOWN;
	}
	buf.resize(result);
	return spdmcpp::RetStat::OK;
}
spdmcpp::RetStat DemuxIOClass::setup_timeout(spdmcpp::timeout_us_t timeout)
{
	constexpr sdeventplus::ClockId cid = sdeventplus::ClockId::Monotonic;
	Emulator.Timeout->set_time(sdeventplus::Clock<cid>(Emulator.Event).now() + std::chrono::microseconds{timeout});
	Emulator.Timeout->set_enabled(sdeventplus::source::Enabled::OneShot);
	return spdmcpp::RetStat::OK;
}


