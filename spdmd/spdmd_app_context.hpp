#pragma once

#include "spdmcpp/context.hpp"
#include "spdmcpp/log.hpp"
#include "utils.hpp"

#include <sdbusplus/bus.hpp>
#include <sdeventplus/event.hpp>
#include <sdeventplus/source/time.hpp>
#include <xyz/openbmc_project/Logging/Entry/server.hpp>

#include <chrono>
#include <sstream>

using namespace std;
using namespace sdbusplus;
using namespace xyz;
using namespace openbmc_project;

/* Define USE_PHOSPHOR_LOGGING to log error messages to phosphor logging module.
 */
#define notUSE_PHOSPHOR_LOGGING

namespace spdmd
{

extern dbus::ServiceHelper inventoryService;

class SpdmdAppContext
{
  public:
    /** @brief ClockId used for specifying various timeouts  */
    static constexpr sdeventplus::ClockId clockId =
        sdeventplus::ClockId::Monotonic;

    /** @brief Time class used for setting up various timeouts  */
    using Clock = sdeventplus::Clock<SpdmdAppContext::clockId>;

    /** @brief Time class used for setting up various timeouts  */
    using Timer = sdeventplus::source::Time<clockId>;

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
    bool reportError(const string& message)
    {
        return reportLog(Logging::server::Entry::Level::Error, message);
    }

    /** @brief Report a notice severity message to phosphor logging object */
    bool reportNotice(const string& message)
    {
        return reportLog(Logging::server::Entry::Level::Notice, message);
    }

  protected:
    /** @brief Set of EIDs to automatically measure, if empty all devices are
     * measured */
    std::set<uint8_t> cachedMeasurements;

    /** @brief Configured startup delay before performing automatic measurement
     */
    std::chrono::seconds measureOnDiscoveryDelay{60};

    /** @brief Indicates whether devices will be automatically measured */
    bool measureOnDiscovery = false;

    /** @brief This indicates measureOnDiscovery is true and
     * cachedMeasurementsDelay has already passed */
    bool measureOnDiscoveryActive = false;

    /** @brief call to check if the given EID should be measured right now */
    bool shouldMeasureEID(uint8_t eid) const
    {
        if (measureOnDiscoveryActive)
        {
            if (cachedMeasurements.empty())
            {
                return true; // this means "all" was selected
            }
            if (cachedMeasurements.contains(eid))
            {
                return true;
            }
        }
        return false;
    }

  private:
    bool reportLog(Logging::server::Entry::Level severity,
                   const string& message)
    {
        if ((severity == Logging::server::Entry::Level::Error) &&
            (log.logLevel >= spdmcpp::LogClass::Level::Error))
        {
            std::cerr << message;
        }
        else if ((severity == Logging::server::Entry::Level::Notice) &&
                 (log.logLevel >= spdmcpp::LogClass::Level::Notice))
        {
            log.getOstream() << message;
        }

#ifdef USE_PHOSPHOR_LOGGING
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
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            std::cerr << "ERROR CREATING LOG " << e.what() << "\n";
            return false;
        }
#endif

        return true;
    }
};

} // namespace spdmd
