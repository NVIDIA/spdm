/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "config.h"

#include "common_headers/utils.hpp"
#include "spdmcpp/context.hpp"
#include "spdmcpp/log.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <nlohmann/json.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Logging/Entry/server.hpp>

#include <chrono>
#include <optional>
#include <sstream>

/* Define USE_PHOSPHOR_LOGGING to log error messages to phosphor logging module.
 */
#define notUSE_PHOSPHOR_LOGGING

namespace spdmd
{

namespace obmcprj = sdbusplus::xyz::openbmc_project;

class SpdmdAppContext
{
    static constexpr auto confFile = SPDM_JSON_CONF_FILE_NAME;

  public:
    /** @brief SPDM requester context class */
    spdmcpp::ContextClass context;

    explicit SpdmdAppContext(std::ostream& logOutStream);
    SpdmdAppContext(const SpdmdAppContext&) = delete;
    SpdmdAppContext& operator=(const SpdmdAppContext&) = delete;
    SpdmdAppContext(SpdmdAppContext&&) = delete;
    SpdmdAppContext& operator=(SpdmdAppContext&&) = delete;
    ~SpdmdAppContext() = default;

    /** @brief Report an error severity message to phosphor logging object */
    bool reportError(const string& message)
    {
        return reportLog(obmcprj::Logging::server::Entry::Level::Error,
                         message);
    }

    /** @brief Report a notice severity message to phosphor logging object */
    bool reportNotice(const string& message)
    {
        return reportLog(obmcprj::Logging::server::Entry::Level::Notice,
                         message);
    }

    /** @brief Get reference to logger object
     *
     */
    spdmcpp::LogClass& getLog()
    {
        return std::ref(log);
    }

    /** @brief Verify json conf file, if it contains given property name for
     * given eid and if yes, then return this json property value */
    template <typename T>
    std::optional<T> getPropertyByEid(uint8_t eid,
                                      const std::string& property) const
    {
        static constexpr auto confEndpoints = "endpoints";
        static constexpr auto confEID = "eid";
        nlohmann::json ret;

        if (!conf.contains(confEndpoints))
        {
            return std::nullopt;
        }

        auto eps = conf[confEndpoints];
        if (!eps.is_array())
        {
            return std::nullopt;
        }

        for (const auto& it : eps)
        {
            if (!it.contains(confEID))
            {
                continue;
            }
            if (!it[confEID].is_number_unsigned())
            {
                continue;
            }
            if (it[confEID] != eid)
            {
                continue;
            }
            if (it.contains(property))
            {
                return it[property].get<T>();
            }
        }
        return std::nullopt;
    }

    /** @brief Get Bus */
    auto& getConn()
    {
        return *conn;
    }

    /** @brief GET IO context */
    auto& getIo()
    {
        return io;
    }

    /** @brief Main asio bus loop */
    int loop()
    {
        return io.run();
    }

    /** @brief Connect to the dbus
     * @param[in] busName - Bus name to connect to
     */
    void connectDBus(const std::string& busName);

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

    /** @brief Meas timer */
    void setupMeasurementDelay();

  private:
    bool reportLog(obmcprj::Logging::server::Entry::Level severity,
                   const string& message);

    /** @brief Start the watchdog timer
     */
    void startWatchdog();

    /** @brief Watchdog refresh function */
    void scheduleWatchdog(std::chrono::microseconds interval);

    /** @brief Log object used to log debug messages */
    spdmcpp::LogClass log;

    /** @brief Configuration data object */
    nlohmann::json conf;

    /** @brief Asio context */
    boost::asio::io_context io;

    /** @brief dbus connection */
    std::unique_ptr<sdbusplus::asio::connection> conn;

    /** @brief Measurement daley timer*/
    std::unique_ptr<boost::asio::steady_timer> measurementDelayTimer;

    /** @brief Watchdog refresh timer */
    std::unique_ptr<boost::asio::steady_timer> watchdogTimer;
};

} // namespace spdmd
