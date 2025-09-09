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

#include "spdmcpp/common.hpp"
#include "spdmd_app_context.hpp"
#include "xyz/openbmc_project/Association/Definitions/server.hpp"
#include "xyz/openbmc_project/Attestation/ComponentIntegrity/server.hpp"
#include "xyz/openbmc_project/Attestation/IdentityAuthentication/server.hpp"
#include "xyz/openbmc_project/Certs/Certificate/server.hpp"
#include "xyz/openbmc_project/Inventory/Item/TrustedComponent/server.hpp"
#include "xyz/openbmc_project/Object/Enable/server.hpp"
#include "xyz/openbmc_project/SPDM/Responder/server.hpp"

#include <boost/asio/steady_timer.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdbusplus/timer.hpp>
#include <spdmcpp/connection.hpp>
#include <spdmcpp/mctp_support.hpp>

#include <map>
#include <memory>

namespace spdmd
{

namespace dbus_api
{

class Responder;

/**
 * @struct Responder creation parameters
 */
struct ResponderArgs
{
    uint8_t eid;
    std::string uuid;
    std::string medium;
    std::string bindingType;
    sdbusplus::message::object_path mctpPath;
    sdbusplus::message::object_path inventoryPath;
    std::string socketPath;
};

/** @class MctpTransportClass
 *  @brief Support class for transport through the mctp-demux-daemon with
 * timeouts handled by boost asio
 */
// NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class MctpTransportClass : public spdmcpp::MctpTransportClass
{
  public:
    MctpTransportClass(uint8_t eid, Responder& resp, std::string medium,
                       spdmcpp::LogClass& logIn) :
        spdmcpp::MctpTransportClass(eid), transportMedium(std::move(medium)),
        responder(resp), log(logIn)
    {}
    ~MctpTransportClass() override = default;

    spdmcpp::RetStat setupTimeout(spdmcpp::timeout_ms_t timeout) override;

    bool clearTimeout() override;

    auto getTransportMedium()
    {
        return transportMedium;
    }

  protected:
    std::string transportMedium;
    Responder& responder;
    std::unique_ptr<boost::asio::steady_timer> timer;
    spdmcpp::LogClass& log;
    void timeoutCallback();
};

using ResponderIntf = sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::SPDM::server::Responder,
    sdbusplus::xyz::openbmc_project::Association::server::Definitions,
    sdbusplus::xyz::openbmc_project::Object::server::Enable,
    sdbusplus::xyz::openbmc_project::Certs::server::Certificate,
    sdbusplus::xyz::openbmc_project::Attestation::server::ComponentIntegrity,
    sdbusplus::xyz::openbmc_project::Attestation::server::
        IdentityAuthentication,
    sdbusplus::xyz::openbmc_project::Inventory::Item::server::TrustedComponent>;

/** @class Responder
 *  @brief OpenBMC SPDM.Responder implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.SPDM.Responder DBus APIs.
 */
class Responder : public ResponderIntf, std::enable_shared_from_this<Responder>
{
  public:
    Responder() = delete;
    Responder(const Responder&) = delete;
    Responder& operator=(const Responder&) = delete;
    Responder(Responder&&) = delete;
    Responder& operator=(Responder&&) = delete;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     *  @param[in] eid - MCTP EndpointID of the responder
     *  @param[in] inventoryPath - Used for the object-manager association
     *  @param[in] transportMedium - Responder base transport medium
     *  @param[in] bindingType - Responder binding type
     *  @param[in] socketPath      - IO device path
     */
    Responder(SpdmdAppContext& appCtx, const std::string& path, uint8_t eid,
              const sdbusplus::message::object_path& mctpPath,
              const sdbusplus::message::object_path& inventPath,
              std::string transportMedium, std::string bindingType,
              std::string socketPath);

    ~Responder() override;

    void refresh(uint8_t slot, std::vector<uint8_t> nonc,
                 std::vector<uint8_t> measurementIndices,
                 uint32_t sessionId) override;

#if FETCH_SERIALNUMBER_FROM_RESPONDER != 0
    void refreshSerialNumber();
#endif

    spdmcpp::LogClass& getLog()
    {
        return log;
    }

    std::string getTransportMedium() const
    {
        return transportMedium;
    }

    uint8_t getEid() const
    {
        return eid;
    }

    /** @brief Event callback for receiving events
     *  @param[inout] bus - Buffer containing the data, note that after the call
     * the contents of buf will be effectively clobbered
     */
    spdmcpp::RetStat handleEvent(
        spdmcpp::EventClass& event) // cppcheck-suppress constParameter
    {
        return (this->*eventHandler)(event);
    }

    auto& getAppCtx()
    {
        return appContext;
    }
    /** @brief Update responder verification status for identity authentication
     */
    void updateResponderVerificationStatus();

  protected:
    using MeasurementsContainerType =
        std::vector<std::tuple<uint8_t, uint8_t, std::vector<uint8_t>>>;
    using CertificatesContainerType =
        std::vector<std::tuple<uint8_t, std::string>>;

    SpdmdAppContext& appContext;

    spdmcpp::LogClass& log;
    spdmcpp::ConnectionClass connection;
    MctpTransportClass transport;
    sdbusplus::message::object_path inventoryPath;
    std::string transportMedium;
    std::string bindingType;
    uint8_t eid;

    spdmcpp::RetStat (Responder::*eventHandler)(spdmcpp::EventClass& event) =
        nullptr;

    void updateVersionInfo();
    void updateAlgorithmsInfo();
    void updateCertificatesInfo();
    void updateLastUpdateTime();
    void updateCapabilities();
    void syncSlotsInfo();

    void handleError(spdmcpp::RetStat rs);
    spdmcpp::RetStat handleEventForRefresh(spdmcpp::EventClass& event);
#if FETCH_SERIALNUMBER_FROM_RESPONDER != 0
    spdmcpp::RetStat handleEventForSerialNumber(spdmcpp::EventClass& event);
#endif

  private:
    /** @brief Update serial number in the inventory
     * @param[in] serialData Serial number data
     */
    void setSerialNumberAsync(const std::vector<uint8_t>& serialData);

    /** @brief Parse a PEM-formatted certificate and fill the certificate info
     *  @param[in] certPEM - PEM-formatted certificate string to parse
     *  @details Parses the provided PEM certificate string and populates the
     *           internal certificate information structures. The certificate
     *           is expected to be in valid PEM format.
     */
    void parseAndFillCertificate(const std::string& certPEM);
};

} // namespace dbus_api
} // namespace spdmd
