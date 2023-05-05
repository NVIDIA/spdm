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

/* Define USE_PHOSPHOR_LOGGING to log error messages to phosphor logging module.
 */
#define notUSE_PHOSPHOR_LOGGING

namespace spdmd
{

namespace obmcprj = sdbusplus::xyz::openbmc_project;
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

    SpdmdAppContext(sdeventplus::Event&& e, sdbusplus::bus::bus&& b,
                     std::ostream& logOutStream);
    SpdmdAppContext(const SpdmdAppContext&) = delete;
    SpdmdAppContext& operator=(const SpdmdAppContext&) = delete;
    SpdmdAppContext(SpdmdAppContext&&) = delete;
    SpdmdAppContext& operator=(SpdmdAppContext&&) = delete;
    ~SpdmdAppContext() = default;

    /** @brief Report an error severity message to phosphor logging object */
    bool reportError(const string& message)
    {
        return reportLog(obmcprj::Logging::server::Entry::Level::Error, message);
    }

    /** @brief Report a notice severity message to phosphor logging object */
    bool reportNotice(const string& message)
    {
        return reportLog(obmcprj::Logging::server::Entry::Level::Notice, message);
    }

    /** @brief Get reference to logger object
     *
     */
    spdmcpp::LogClass& getLog()
    {
        return std::ref(log);
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
    bool shouldMeasureEID(uint8_t eid) const;

  private:
    bool reportLog(obmcprj::Logging::server::Entry::Level severity,
                   const string& message);

   /** @brief Log object used to log debug messages */
    spdmcpp::LogClass log;

};

} // namespace spdmd
