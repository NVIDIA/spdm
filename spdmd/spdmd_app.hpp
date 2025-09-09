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
#include "dbus_impl_responder.hpp"
#include "spdmcpp/common.hpp"
#include "spdmcpp/context.hpp"
#include "spdmcpp/log.hpp"
#include "spdmcpp/mctp_support.hpp"
#include "spdmd_app_context.hpp"

#include <boost/asio.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/steady_timer.hpp>
#include <sdbusplus/asio/connection.hpp>

#include <memory>
#include <unordered_map>

using namespace spdmd;
using namespace spdmcpp;
using namespace sdbusplus;

namespace spdmd
{

using MctpBinding = std::string;

using MctpMedium = std::string;

using Priority = int;

/**
 * @brief MCTP Medium priority table ordering by bandwidth
 */
static std::unordered_map<MctpMedium, Priority> mediumPriority = {
    {"xyz.openbmc_project.MCTP.Endpoint.MediaTypes.PCIe", 0},
    {"xyz.openbmc_project.MCTP.Endpoint.MediaTypes.USB", 1},
    {"xyz.openbmc_project.MCTP.Endpoint.MediaTypes.SPI", 2},
    {"xyz.openbmc_project.MCTP.Endpoint.MediaTypes.I3C", 3},
    {"xyz.openbmc_project.MCTP.Endpoint.MediaTypes.KCS", 4},
    {"xyz.openbmc_project.MCTP.Endpoint.MediaTypes.Serial", 5},
    {"xyz.openbmc_project.MCTP.Endpoint.MediaTypes.SMBus", 6}};

/**
 * @brief MCTP Binding Type priority table ordering by bandwidth
 */
static std::unordered_map<MctpBinding, Priority> bindingPriority = {
    {"xyz.openbmc_project.MCTP.Binding.BindingTypes.PCIe", 0},
    {"xyz.openbmc_project.MCTP.Binding.BindingTypes.USB", 1},
    {"xyz.openbmc_project.MCTP.Binding.BindingTypes.SPI", 2},
    {"xyz.openbmc_project.MCTP.Binding.BindingTypes.I3C", 3},
    {"xyz.openbmc_project.MCTP.Binding.BindingTypes.KCS", 4},
    {"xyz.openbmc_project.MCTP.Binding.BindingTypes.Serial", 5},
    {"xyz.openbmc_project.MCTP.Binding.BindingTypes.SMBus", 6}};

class SpdmdApp : public SpdmdAppContext
{
  public:
    SpdmdApp(const SpdmdApp&) = delete;
    SpdmdApp(SpdmdApp&&) = delete;
    SpdmdApp& operator=(const SpdmdApp&) = delete;
    SpdmdApp& operator=(SpdmdApp&&) = delete;
    ~SpdmdApp() = default;

    /** @brief Constructs the SPDM daemon
     *
     */
    SpdmdApp();

    /** @brief Setup CLI for SPDM daemon
     *
     */
    void setupCli(int argc, char** argv);

    /** @brief Connect SPDM daemon to MCTP
     *  @details Safe to call redundantly if necessary,
     * it'll create only one connection.
     */
    void connectMCTP(const std::string& sockPath);

    /** @brief Connect SPDM daemon to MCTP in kernel
     */
    void connectMCTP();

    /** @brief Sets up the automatic measurement delay according to commandline
     * parameters
     */
    void setupMeasurementDelay();

    /** @brief Check the UUIDs in the existing disovery table responder
     * and create responder when UUID is not exist, or re-create responder
     * if the higher priority reponder is detected
     * @param respArgs Discovered response arguments
     *
     */
    void discoveryUpdateResponder(const dbus_api::ResponderArgs& respArg);

  private:
    /** @brief SPDMD callback signal called
     *
     */
    void mctpCallback(uint32_t revents, spdmcpp::MctpIoClass& mctpIo);

    /** @brief Create new Responder object
     *
     */
    void createResponder(const dbus_api::ResponderArgs& args);

    /**
     * @brief Determines if a responder needs to be recreated based on medium
     * and binding type priorities
     *
     * This function implements a priority-based comparison logic for transport
     * mediums and binding types. The decision to recreate a responder is based
     * on the following rules:
     * 1. If the medium types are different, compare their priorities
     * 2. If the medium priorities are equal, compare the binding type
     * priorities
     * 3. A responder is recreated if the new configuration has equal or higher
     * priority
     *
     * @param currMedium Current transport medium type
     * @param newMedium New transport medium type
     * @param currBinding Current binding type string
     * @param newBinding New binding type string
     * @return true if the responder should be recreated based on priority
     * comparison
     */
    bool needRecreateResponder(const std::string& currMedium,
                               const std::string& newMedium,
                               const std::string& currBinding,
                               const std::string& newBinding);

    /** @brief verbose - debug level for SPDM daemon */
    spdmcpp::LogClass::Level verbose = spdmcpp::LogClass::Level::Emergency;

    /** @brief Event handler for MCTP events - used for transmission purposes
     * over MCTP */
    std::unordered_map<std::string,
                       std::unique_ptr<boost::asio::posix::stream_descriptor>>
        mctpEvents;

    /** @brief Event handler for MCTP events - used for transmission purposes
     * over af*/
    std::unique_ptr<boost::asio::posix::stream_descriptor> afMctpEvent;

    /** @brief Array of all responder objects, managed by SPDM daemon */
    std::vector<std::shared_ptr<dbus_api::Responder>> responders;
    /** @brief Discovery responders by UUID map*/
    std::map<std::string, dbus_api::ResponderArgs> resp_discovery;

    /** @brief Buffer for packets received from responders over MCTP */
    std::vector<uint8_t> packetBuffer;

    /** @brief Timer for handling the measurement delay
     */
    std::unique_ptr<boost::asio::steady_timer> measurementDelayTimer;

    /** @brief Callback for the automatic measurement delay
     */
    void measurementDelayCallback();

    /** @brief checks if the given eid should be measured and issues a refresh
     *  @returns true if refresh was called, false otherwise
     */
    bool autoMeasure(uint8_t eid) const;
};

} // namespace spdmd
