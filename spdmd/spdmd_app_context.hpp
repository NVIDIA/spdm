#pragma once

#include "spdmcpp/context.hpp"
#include "spdmcpp/log.hpp"

#include <sdbusplus/bus.hpp>
#include <sdeventplus/event.hpp>
#include <xyz/openbmc_project/Logging/Entry/server.hpp>

#include <chrono>
#include <sstream>

using namespace std;
using namespace sdbusplus;
using namespace xyz;
using namespace openbmc_project;

namespace spdmd
{

class SpdmdAppContext
{
  public:
    /** @brief SPDM requester context class */
    spdmcpp::ContextClass context;

    /** @brief SPDM requester event management */
    sdeventplus::Event event;

    /** @brief SPDM requester used dbus */
    sdbusplus::bus::bus bus;

    /** @brief Log object used to log debug messages */
    spdmcpp::LogClass log;

    SpdmdAppContext(sdeventplus::Event&& e, sdbusplus::bus::bus&& b,
                    std::ostream& logOutStream) :
        event(std::move(e)),
        bus(std::move(b)), log(logOutStream)
    {}

    /** @brief Report an error severity message to phosphor logging object */
    bool reportError(string message)
    {
        return reportLog(Logging::server::Entry::Level::Error, message);
    }

    /** @brief Report a critical severity message to phosphor logging object */
    bool reportCritical(string message)
    {
        return reportLog(Logging::server::Entry::Level::Critical, message);
    }

    /** @brief Report an alert severity message to phosphor logging object */
    bool reportAlert(string message)
    {
        return reportLog(Logging::server::Entry::Level::Alert, message);
    }

    /** @brief Report a notice severity message to phosphor logging object */
    bool reportNotice(string message)
    {
        return reportLog(Logging::server::Entry::Level::Notice, message);
    }

  private:
    bool reportLog(Logging::server::Entry::Level severity, string message)
    {
        auto method = bus.new_method_call(
            "xyz.openbmc_project.Logging", "/xyz/openbmc_project/logging",
            "xyz.openbmc_project.Logging.Create", "Create");

        method.append(message);

        auto severityS = Logging::server::convertForMessage(severity);

        method.append(severityS);

        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        string telemetries = std::ctime(&time);
        telemetries.resize(telemetries.size() - 1);

        string resolution = (severity < Logging::server::Entry::Level::Warning)
                                ? "Contact NVIDIA Support"
                                : "";

        method.append(std::array<std::pair<std::string, std::string>, 3>(
            {{{"xyz.openbmc_project.Logging.Entry.Resolution", resolution},
              {"DEVICE_EVENT_DATA", telemetries},
              {"namespace", "spdmd"}}}));

        try
        {
            auto reply = bus.call(method);
            std::vector<std::tuple<uint32_t, std::string,
                                   sdbusplus::message::object_path>>
                users;
            reply.read(users);
            for (auto& user : users)
            {
                std::cerr << std::get<std::string>(user) << "\n";
            }
            return true;
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            std::cerr << "ERROR CREATING LOG " << e.what() << "\n";
            return false;
        }
    }
};

} // namespace spdmd
