
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
