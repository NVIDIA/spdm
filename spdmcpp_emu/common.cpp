
#include <common.hpp>
#include <spdmcpp/context.hpp>

// #include <sdeventplus/utility/timer.hpp>
#include <sdeventplus/source/time.hpp>

EmulatorBaseIOClass::EmulatorBaseIOClass(EmulatorBase& emu) : emulator(emu)
{
    auto timeCb = [this](sdeventplus::source::Time<cid>& /*source*/,
                         sdeventplus::source::Time<cid>::TimePoint /*time*/) {
        spdmcpp::RetStat rs = emulator.getConnection().handleTimeout();
        if (rs == spdmcpp::RetStat::ERROR_TIMEOUT)
        {
            emulator.event.exit(0);
        }
    };

    // TODO AUTO POINTER
    timeout = new sdeventplus::source::Time<cid>(
        emulator.event, sdeventplus::Clock<cid>(emulator.event).now(),
        std::chrono::milliseconds{1}, std::move(timeCb));
    timeout->set_enabled(sdeventplus::source::Enabled::Off);
}

spdmcpp::RetStat EmulatorBaseIOClass::setupTimeout(spdmcpp::timeout_us_t time)
{
    timeout->set_time(sdeventplus::Clock<cid>(emulator.event).now() +
                      std::chrono::microseconds{time});
    timeout->set_enabled(sdeventplus::source::Enabled::OneShot);
    return spdmcpp::RetStat::OK;
}

spdmcpp::RetStat EMUIOClass::write(const std::vector<uint8_t>& buf,
                                   spdmcpp::timeout_us_t /*timeout*/)
{
    if (!emulator.sendPlatformData(
            SocketCommandEnum::SOCKET_SPDM_COMMAND_NORMAL, buf))
    {
        return spdmcpp::RetStat::ERROR_UNKNOWN;
    }
    return spdmcpp::RetStat::OK;
}
spdmcpp::RetStat EMUIOClass::read(std::vector<uint8_t>& buf,
                                  spdmcpp::timeout_us_t /*timeout*/)
{
    auto response = SocketCommandEnum::SOCKET_SPDM_COMMAND_UNKOWN;
    if (!emulator.receivePlatformData(response, buf))
    {
        return spdmcpp::RetStat::ERROR_UNKNOWN;
    }
    SPDMCPP_ASSERT(response == SocketCommandEnum::SOCKET_SPDM_COMMAND_NORMAL);
    return spdmcpp::RetStat::OK;
}

spdmcpp::RetStat DemuxIOClass::write(const std::vector<uint8_t>& buf,
                                     spdmcpp::timeout_us_t /*timeout*/)
{
    size_t sent = 0;
    while (sent < buf.size())
    {
        ssize_t ret =
            send(emulator.getSocket(), (void*)&buf[sent], buf.size() - sent, 0);
        if (ret == -1)
        {
            std::cerr << "Send error: " << errno << std::endl;
            return spdmcpp::RetStat::ERROR_UNKNOWN;
        }
        sent += ret;
    }
    return spdmcpp::RetStat::OK;
}
spdmcpp::RetStat DemuxIOClass::read(std::vector<uint8_t>& buf,
                                    spdmcpp::timeout_us_t /*timeout*/)
{
    buf.resize(4096); // MCTP_MAX_MSG
    ssize_t result =
        recv(emulator.getSocket(), (void*)buf.data(), buf.size(), 0);
    if (result == -1)
    {
        buf.clear();
        std::cerr << "Receive error: " << errno << std::endl;
        return spdmcpp::RetStat::ERROR_UNKNOWN;
    }
    if (result == 0)
    {
        buf.clear();
        return spdmcpp::RetStat::ERROR_UNKNOWN;
    }
    buf.resize(result);
    return spdmcpp::RetStat::OK;
}
