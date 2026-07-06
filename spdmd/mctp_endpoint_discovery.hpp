/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0 Licensed
 * under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
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

#include "spdmcpp/common.hpp"
#include "spdmd_app.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <sdbusplus/bus/match.hpp>

#include <array>
#include <chrono>
#include <deque>
#include <map>
#include <unordered_set>

namespace spdmd
{

using mctp_eid_t = uint8_t;
using createResponder_t = bool (*)(mctp_eid_t);
class SpdmdApp;

class MctpDiscovery
{
  public:
    MctpDiscovery() = delete;
    MctpDiscovery(const MctpDiscovery&) = delete;
    MctpDiscovery(MctpDiscovery&&) = delete;
    MctpDiscovery& operator=(const MctpDiscovery&) = delete;
    MctpDiscovery& operator=(MctpDiscovery&&) = delete;
    virtual ~MctpDiscovery() = default;

    /** @brief Constructs the MCTP Discovery object to handle discovery of
     *         MCTP and SPDM enabled devices
     *
     *  @param[in] bus - reference to systemd bus
     *  @param[in] createResponder - reference to create Responder function
     */
    explicit MctpDiscovery(SpdmdApp& spdmApp);

    /* The change is added to address the issue of mismatched data types between
     * the control daemon and the code construct for the eid data type
     */
    using EidType = std::optional<std::variant<uint32_t, uint8_t>>;

  private:
    struct Object
    {
        sdbusplus::object_path path;
        dbus::InterfaceMap interfaces;
        bool isValid() const
        {
            return !path.filename().empty();
        }
    };

    /** @brief reference to the systemd bus */
    sdbusplus::bus_t& bus;

    /** @brief reference to the SPDM app, used to create responder */
    SpdmdApp& spdmApp;

#ifndef DISCOVERY_ONLY_FROM_MCTP_CONTROL
    /** @brief Used to watch for new PLDM inventory objects */
    sdbusplus::bus::match_t inventoryMatch;

    /** @brief Used to watch Common.UUID property writes on inventory objects.
     *
     *  EM creates the RoT chassis carrying SPDMResponder with an empty UUID
     *  at probe time; pldm writes the endpoint UUID once its own discovery
     *  completes. The InterfacesAdded signal above therefore carries no
     *  usable UUID - the endpoint join becomes possible only when the
     *  property changes to a non-empty value. */
    sdbusplus::bus::match_t inventoryUuidMatch;
#endif
    /** @brief Used to watch for new MCTP endpoints */
    unique_ptr<sdbusplus::bus::match_t> mctpMatch;
    std::unordered_map<std::string, unique_ptr<dbus::ServiceHelper>>
        mctpControlServices;

    /** @brief Used to watch for new CCSM interface */
    unique_ptr<sdbusplus::bus::match_t> ccsmChange;

    /** @brief CCSM ready variable indicates MCTP ready */
    bool ccsmReady{};

    /** @brief Set once the first GetManagedObjects round completes for
     *  any MCTP control service, even if the returned endpoint list is
     *  empty. Layered on top of `ccsmReady`; external "ready to attest"
     *  checks should consult `isMctpDiscoveryComplete() && ccsmReady` so
     *  they don't see an empty inventory as "done" while the mapper is
     *  still unhealthy.
     */
    bool mctpDiscoveryComplete{false};

  public:
    /** @brief Discovery-readiness gate for external "ready to attest"
     *         checks. Returns true after at least one successful
     *         per-service GetManagedObjects round has completed.
     */
    [[nodiscard]] bool isMctpDiscoveryComplete() const noexcept
    {
        return mctpDiscoveryComplete;
    }

  private:
    /** @brief MCTP ready variable indicates MCTP ready */
    void initCsmStatus();

#ifndef DISCOVERY_ONLY_FROM_MCTP_CONTROL
    /** @brief Inventory new object signal queue */
    std::deque<std::pair<sdbusplus::object_path, dbus::InterfaceMap>>
        inventorySignalQueue;

    /** @brief Per-path UUID cache for EM-sourced inventory objects.
     *
     *  EM emits one InterfacesAdded signal per interface in lexicographic
     *  order.  UUID (xyz.openbmc_project.Common.UUID) arrives in a separate,
     *  earlier signal than SPDMResponder.  The UUID string is cached here so
     *  it can be injected when the SPDMResponder signal arrives without it.
     *  The entry is removed once the object is fully processed.
     */
    std::map<sdbusplus::object_path, std::string> uuidCache;
#endif

    /** @brief Called when a new mctp endpoint is discovered */
    void mctpNewObjectSignal(const sdbusplus::object_path& objectPath,
                             const dbus::InterfaceMap& interfaces);

#ifndef DISCOVERY_ONLY_FROM_MCTP_CONTROL
    /** @brief Called when a new PLDM inventory object is discovered */
    void inventoryNewObjectSignal(const sdbusplus::object_path& objectPath,
                                  const dbus::InterfaceMap& interfaces);

    /** @brief Called when Common.UUID changes on an inventory object.
     *
     *  Verifies the object carries SPDMResponder (UUID writes also land on
     *  plain inventory in the same subtree) and re-enters
     *  inventoryNewObjectSignal with the now-usable UUID so the endpoint
     *  join and responder creation run. */
    void inventoryUUIDChangedSignal(sdbusplus::message::message& msg);

    /** @brief Scans inventory at startup for SPDMResponder objects
     *  that already carry a non-empty Common.UUID.
     *
     *  inventoryUuidMatch only catches live PropertiesChanged signals.
     *  On platforms where NSM writes the UUID via a fast direct MCTP
     *  path before spdmd registers the match (e.g. GB200NVL HMC
     *  ERoT_BMC_0 via EID 10), the signal is missed and no responder
     *  is created. This scan runs once after all signal handlers are
     *  registered to catch UUIDs that arrived early. */
    void scanExistingInventoryUUIDs();

    void onScanSubtreeReply(boost::system::error_code ec,
                            sdbusplus::message::message& replyMsg);

    void onScanUuidOwnerReply(
        boost::system::error_code ec,
        const std::map<std::string, std::vector<std::string>>& services,
        sdbusplus::object_path objPath);

    void onScanUuidValueReply(std::string uuid, sdbusplus::object_path objPath);
#endif

    /** @brief Try calling spdmApp.ConnectMCTP() with user-space mctp stack. */
    void tryConnectMCTP(const std::string& sockPath);

    /** MCTP handle callback */

    void mtcpCallback(uint32_t revents, spdmcpp::MctpIoClass& mctpIo);

  public:
    static constexpr uint8_t mctpTypeSPDM = 5;
    static constexpr uint8_t invalidEidValue = 0xFF;

  private:
    static constexpr auto mapperService = "xyz.openbmc_project.ObjectMapper";
    static constexpr auto mapperPath = "/xyz/openbmc_project/object_mapper";
    static constexpr auto mapperInterface = "xyz.openbmc_project.ObjectMapper";

    /** @brief MCTP d-bus interface name  */
    static constexpr auto mctpEndpointIntfName =
        "xyz.openbmc_project.MCTP.Endpoint";

    /** @brief MCTP d-bus interface, property name EID  */
    static constexpr auto mctpEndpointIntfPropertyEid = "EID";

    /** @brief MCTP get medium type*/
    static constexpr auto mctpEndpointIntfPropertyMediumType = "MediumType";

    /** @brief MCTP d-bus interface, property name EID  */
    static constexpr auto mctpEndpointIntfPropertySupportedMessageTypes =
        "SupportedMessageTypes";

    /** @brief SPDM responder inventory interface name */
    static constexpr auto inventorySPDMResponderIntfName =
        "xyz.openbmc_project.Inventory.Item.SPDMResponder";

    /** @brief SPDM responder inventory base path */
    static constexpr auto inventorySPDMResponderBasePath =
        "/xyz/openbmc_project/inventory/system/chassis/";

    /** @brief SPDM responder inventory subtree for path_namespace match
     *         rules, which reject the trailing slash the base path carries */
    static constexpr auto inventorySPDMResponderNamespace =
        "/xyz/openbmc_project/inventory/system/chassis";

    /** @brief Common d-bus interface, property UUID */
    static constexpr auto uuidIntfName = "xyz.openbmc_project.Common.UUID";

    /** @brief MCTP d-bus interface, property UUID */
    static constexpr auto mctpUUIDIntfName = "xyz.openbmc_project.MCTP.UUID";

    /** @brief MCTP transport socket interface name */
    static constexpr auto mctpTransportSockIntfName =
        "xyz.openbmc_project.Common.UnixSocket";

    /** @brief MCTP transport sock type */
    static constexpr auto mctpTransportSockIntfType = "Address";

    static constexpr auto uuidIntfPropertyUUID = "UUID";
    //     static constexpr auto mctpEndpointIntfPropertyUUID =
    //         "SupportedMessageTypes";

    /** @brief MCTP d-bus Binding interface name  */
    static constexpr auto mctpBindingIntfProperty =
        "xyz.openbmc_project.MCTP.Binding";

    static constexpr auto mctpBindingIntfPropertyBindType = "BindingType";

/** @brief MCTP discovery path */
#ifdef MCTP_IN_KERNEL
    static constexpr auto mctpPath = "/au/com/codeconstruct/mctp1";
#else
    static constexpr auto mctpPath = "/xyz/openbmc_project/mctp";
#endif
    /** @brief CCSM state manager service */
    static constexpr auto configurableStateManagerService =
        "xyz.openbmc_project.State.ConfigurableStateManager";

    /** @brief CCSM state ready interface name */
    static constexpr auto csmFeatureReadyStateIntfName =
        "xyz.openbmc_project.State.FeatureReady";

    /** @brief CCSM enable state enabled */
    static constexpr auto csmFeatureReadyStateEnabled =
        "xyz.openbmc_project.State.FeatureReady.States.Enabled";

    /** @brief MCTP configuration manager path */
    static constexpr auto configurableStateManagerMctpPath =
        "/xyz/openbmc_project/state/configurableStateManager/MCTP";

    /** @brief CCSM  */
    static constexpr auto configurableStateManagerPath =
        "/xyz/openbmc_project/state/configurableStateManager";

    /** @brief Object manager service */
    static constexpr auto objMgrSvc = "org.freedesktop.DBus.ObjectManager";

    /** @brief Get EID value from MCTP objects, which implement SPDM
     *  @returns EID or invalidEid (256) in case of error
     */
    EidType getEid(const dbus::InterfaceMap& interfaces);

    /** @brief Get EID value from MCTP objects, which implement SPDM
     *  @returns EID or invalidEid (256) in case of error
     */
    EidType getEid(const std::map<std::string, dbus::Value>& properties);

    /**
     * @brief Extracts binding type value from the object's interfaces
     *
     * @param interfaces collection map with interfaces and its properties
     * @return std::optional<std::string> with binding type or false if failed
     */
    std::string getBindingType(const dbus::InterfaceMap& interfaces);

    /**
     * @brief Extracts transport medium value from the object's interfaces
     *
     * @param interfaces collection map with interfaces and its properties
     * @return std::string with transport medium or empty string if failed
     */
    std::string getMediumType(const dbus::InterfaceMap& interfaces);

    /** @brief Get Transport Unix socket from the endpoint
     *  @param[in] interfaces - Map of interfaces and their properties
     *  @return String with the Unix socket path or empty string if not found
     */
    std::string getTransportSocket(const dbus::InterfaceMap& interfaces);

    /** @brief Extract UUID value from the object's interfaces
     *  @param[in] interfaces - Map of interfaces and their properties
     *  @return String with the UUID value or empty string if not found
     */
    std::string getUUID(const dbus::InterfaceMap& interfaces);

    /** @brief Extract property value from the service and path asynchronously
     *  @param[in] service - The D-Bus service name
     *  @param[in] path - The D-Bus object path
     *  @param[in] interface - The D-Bus interface name
     *  @param[in] property - The property name to retrieve
     *  @param[in] callback - Function to call with the retrieved string value
     */
    void getPropertyValueAsync(const std::string& service,
                               const std::string& path,
                               const std::string& interface,
                               const std::string& property,
                               std::function<void(std::string)> callback);

    /** @brief Get an object from MCTP.Control with the provided UUID
     * asynchronously
     *  @param[in] uuid - The UUID to search for
     *  @param[in] callback - Function to call with the retrieved Object
     */
    void getMCTPObjectAsync(const std::string& uuid,
                            std::function<void(Object)> callback);

    /** @brief Get a path from the inventory to an object with the provided UUID
     * asynchronously
     *  @param[in] uuid - The UUID to search for
     *  @param[in] callback - Function to call with the retrieved object path
     */
    void getInventoryPathAsync(
        const std::string& uuid,
        std::function<void(sdbusplus::object_path)> callback);

    /** @brief Get the unique services from the object mapper asynchronously
     *  @param[in] callback - Function to call with the set of service names
     */
    void getMCTPServicesAsync(
        std::function<void(std::unordered_set<std::string>)> callback);

    /** @brief Setup MCTP services
     *  Discovers and initializes all available MCTP control services
     */
    void setupMCTPServices();

  protected:
    /** @brief Backoff schedule for bounded retry of mapper +
     *  GetManagedObjects failures: 50ms → 200ms → 1s → 3s → 5s
     *  (cumulative ~9.25s). Overridable by tests via the virtual
     *  `getMapperRetryBackoff()` seam below.
     */
    using BackoffSchedule = std::array<std::chrono::milliseconds, 5>;
    static constexpr BackoffSchedule mapperRetryBackoffProd{
        std::chrono::milliseconds{50}, std::chrono::milliseconds{200},
        std::chrono::milliseconds{1000}, std::chrono::milliseconds{3000},
        std::chrono::milliseconds{5000}};

    /** @brief Test seam — override to return a tight (1ms-per-step)
     *         schedule so unit tests don't pay the production ~9.25s
     *         cumulative latency.  Production code calls
     *         `getMapperRetryBackoff()` everywhere.
     */
    virtual BackoffSchedule getMapperRetryBackoff() const
    {
        return mapperRetryBackoffProd;
    }

  private:
    /** @brief Per-async-call retry state — owns the steady_timer used
     *         to schedule the next attempt and tracks attempt count.
     */
    struct RetryState
    {
        size_t attempt{0};
        boost::asio::steady_timer timer;
        explicit RetryState(boost::asio::io_context& io) : timer(io)
        {}
    };

    /** @brief Active retry state for the mapper-side getMCTPServicesAsync
     *         retry chain.  Constructed on first failure; reset to
     *         attempt=0 on success.
     */
    std::unique_ptr<RetryState> mapperRetryState;

    /** @brief Per-service retry state for the
     *         setupMCTPServices → GetManagedObjects retry chain.
     *         Keyed by service name so each service gets its own
     *         independent backoff curve.
     */
    std::unordered_map<std::string, std::unique_ptr<RetryState>>
        getManagedObjectsRetryState;

    /** @brief Schedule the next attempt at mapper-side service discovery
     *         using the backoff schedule.  When attempts are exhausted,
     *         logs an error and invokes the callback with an empty set
     *         (caller already handles empty).
     */
    void scheduleMapperRetry(
        std::function<void(std::unordered_set<std::string>)> callback);

    /** @brief Issue a single GetManagedObjects async call for one
     *         service.  On ec != 0 → schedules a retry via
     *         `scheduleGetManagedObjectsRetry`.  On success →
     *         resets the per-service attempt counter and marks
     *         `mctpDiscoveryComplete = true` BEFORE dispatching
     *         per-endpoint via `mctpNewObjectSignal`.
     */
    void issueGetManagedObjects(const std::string& svc);

    /** @brief Schedule the next attempt at GetManagedObjects for a
     *         specific service using the backoff schedule.  When
     *         attempts are exhausted, logs an error and stops retrying
     *         for that service; other services continue independently.
     */
    void scheduleGetManagedObjectsRetry(const std::string& svc);
};

} // namespace spdmd
