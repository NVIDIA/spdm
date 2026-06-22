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

#include "enumerate_utils.hpp"

#include <common_headers/utils.hpp>
#include <sdbusplus/bus.hpp>
#include <spdmcpp/common.hpp>

#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace spdmt
{

/** @brief Responder info structure used for discovery */
struct ResponderInfo
{
    size_t eid;           //! Endpoint identifier
    std::string path;     //! Responder path
    std::string uuid;     //! UUID responder
    std::string sockPath; //! Unix socket path
};

class EnumerateEndpoints
{
  public:
    /**
     * Enumerate MCTP SPDM endpoints
     */
    explicit EnumerateEndpoints(int m_eid);

    /**
     * @brief Get enumerated responders information
     */
    auto& getRespondersInfo() const noexcept
    {
        return respInfos;
    }

  private:
    /** @brief Explore MCTP spdm objects */
    auto enumerateMCTPDBusObjects(sdbusplus::bus_t& bus, int m_eid) -> void;

    /** @brief Explore a single MCTP item
     *
     * @param path The D-Bus object path of the MCTP item
     * @param ifc The D-Bus interface map containing properties of the MCTP item
     *
     * @return void This method doesn't return a value
     */
    auto exploreMctpItem(const sdbusplus::object_path& path,
                         const DbusInterfaceMap& ifc) -> void;
    /** @brief Get endpoint EID*/
    auto getEid(const DbusInterfaceMap& ifc) -> std::optional<size_t>;
    /** @brief Get endpoint EID*/
    auto getEid(const std::map<std::string, DbusValue>& prop)
        -> std::optional<size_t>;
    /** @brief Get endpoint UUID*/
    auto getUUID(const DbusInterfaceMap& ifc) -> std::string;
    /** @brief Get transport socket */
    auto getUnixSocketAddress(const DbusInterfaceMap& ifc) -> std::string;

    /** @brief Get the unique service from the object mapper
     *
     * @param bus The D-Bus connection to use for querying the object mapper
     * @type bus: sdbusplus::bus_t&
     *
     * @return std::unordered_set<std::string> A set of unique MCTP service
     * names
     */
    auto getMCTPServices(sdbusplus::bus_t& bus, int m_eid)
        -> std::vector<std::pair<std::string, std::string>>;

    /** @brief Extract a particular value from the service and path
     *
     * @param service The name of the D-Bus service to query
     * @param path The object path within the D-Bus service
     * @param interface The D-Bus interface to query
     * @param property The name of the property to retrieve
     *
     * @return std::string The value of the requested property
     */
    auto getPropertyValue(sdbusplus::bus_t& bus, const std::string& service,
                          const std::string& path, const std::string& interface,
                          const std::string& property) -> size_t;

  private:
    std::vector<ResponderInfo> respInfos;
};
} // namespace spdmt