/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
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

/*
 * Copyright (C) NVIDIA Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
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
#include <unordered_set>

#include <sdbusplus/bus/match.hpp>

namespace spdmd
{

extern dbus::ServiceHelper mctpControlService;

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
    ~MctpDiscovery() = default;

    /** @brief Constructs the MCTP Discovery object to handle discovery of
     *         MCTP and SPDM enabled devices
     *
     *  @param[in] bus - reference to systemd bus
     *  @param[in] createResponder - reference to create Responder function
     */
    explicit MctpDiscovery(SpdmdApp& spdmApp);

  private:
    struct Object
    {
        sdbusplus::message::object_path path;
        dbus::InterfaceMap interfaces;
        bool isValid() const
        {
            return !path.filename().empty();
        }
    };

    /** @brief reference to the systemd bus */
    sdbusplus::bus::bus& bus;

    /** @brief reference to the SPDM app, used to create responder */
    SpdmdApp& spdmApp;

#ifndef DISCOVERY_ONLY_FROM_MCTP_CONTROL
    /** @brief Used to watch for new PLDM inventory objects */
    sdbusplus::bus::match_t inventoryMatch;
#endif
    /** @brief Used to watch for new MCTP endpoints */
    std::vector<unique_ptr<sdbusplus::bus::match_t>> mctpMatch;
    std::vector<unique_ptr<dbus::ServiceHelper>> mctpControlServices;


    /** @brief Called when a new mctp endpoint is discovered */
    void mctpNewObjectSignal(const sdbusplus::message::object_path& objectPath, const dbus::InterfaceMap& interfaces);

#ifndef DISCOVERY_ONLY_FROM_MCTP_CONTROL
    /** @brief Called when a new PLDM inventory object is discovered */
    void inventoryNewObjectSignal(const sdbusplus::message::object_path& objectPath, const dbus::InterfaceMap& interfaces);
#endif

    /** @brief Try calling spdmApp.ConnectMCTP() */
    void tryConnectMCTP(const std::string& sockPath);

    /** MCTP handle callback */
    void mtcpCallback(uint32_t revents, spdmcpp::MctpIoClass &mctpIo);


    /** @brief SPDM type of an MCTP message */
    static constexpr uint8_t mctpTypeSPDM = 5;

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

    static constexpr auto inventorySPDMResponderIntfName =
        "xyz.openbmc_project.Inventory.Item.SPDMResponder";

    /** @brief MCTP d-bus interface, property UUID */
    static constexpr auto uuidIntfName = "xyz.openbmc_project.Common.UUID";

    /** @brief MCTP transport socket interface name */
    static constexpr auto mctpTransportSockIntfName =
        "xyz.openbmc_project.Common.UnixSocket";

    /** @brief MCTP transport sock type */
    static constexpr auto mctpTransportSockIntfType =
        "Address";

    static constexpr auto uuidIntfPropertyUUID = "UUID";
    //     static constexpr auto mctpEndpointIntfPropertyUUID =
    //         "SupportedMessageTypes";

    /** @brief MCTP d-bus Binding interface name  */
    static constexpr auto mctpBindingIntfProperty =
        "xyz.openbmc_project.MCTP.Binding";

    static constexpr auto mctpBindingIntfPropertyBindType =
        "BindingType";

    /** @brief MCTP discovery path */
    static constexpr auto mctpPath = "/xyz/openbmc_project/mctp";

    /** @brief Object manager service */
    static constexpr auto objMgrSvc = "org.freedesktop.DBus.ObjectManager";

    /** @brief Get EID value from MCTP objects, which implement SPDM
     *  @returns EID or invalidEid (256) in case of error
     */
    size_t getEid(const dbus::InterfaceMap& interfaces);

    /** @brief Get EID value from MCTP objects, which implement SPDM
     *  @returns EID or invalidEid (256) in case of error
     */
    size_t getEid(const std::map<std::string, dbus::Value>& properties);

    /**
     * @brief Extracts transport medium value from the object's interfaces
     *
     * @param interfaces collection map with interfaces and its properties
     * @return std::optional<spdmcpp::TransportMedium> with transport medium or false if failed
     */
    std::optional<spdmcpp::TransportMedium> getMediumType(const dbus::InterfaceMap& interfaces);

    /**
     * @brief Extracts Internal transport medium value from the object's interfaces
     *
     * @param properties collection of properties that comes from proper interface
     * @return std::optional<spdmcpp::TransportMedium>
     */
    std::optional<spdmcpp::TransportMedium> getInternalMediumType(
        const std::map<std::string, dbus::Value>& properties, std::string_view propName);

    /** @brief Get Transport Unix socket from the endpoint */
    std::string getTransportSocket(const dbus::InterfaceMap& interfaces);

    /** @brief Extract UUID value from the object's interfaces */
    std::string getUUID(const dbus::InterfaceMap& interfaces);

    /** @brief get an object from MCTP.Control with the provided uuid
     */
    Object getMCTPObject(const std::string& uuid);

    /** @brief get a path from the inventory to an object with the provided uuid
     */
    sdbusplus::message::object_path getInventoryPath(const std::string& uuid);

    /** @brief Get the unique service from the object mapper */
    std::unordered_set<std::string> getMCTPServices();

};

} // namespace spdmd
