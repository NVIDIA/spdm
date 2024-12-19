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

#include "enumerate_endpoints.hpp"

#include "enumerate_utils.hpp"

#include <common_headers/utils.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>

#include <iostream>

using namespace spdmcpp;

namespace spdmt
{

size_t invalid_eid = 255;

EnumerateEndpoints::EnumerateEndpoints(int m_eid)
{
#ifdef USE_DEFAULT_DBUS
    auto bus = sdbusplus::bus::new_default();
#else
    auto bus = sdbusplus::bus::new_system();
#endif
    enumerateMCTPDBusObjects(bus, m_eid);
}

auto EnumerateEndpoints::enumerateMCTPDBusObjects(sdbusplus::bus::bus& bus,
                                                  int m_eid) -> void
{

    auto svcNames = getMCTPServices(bus, m_eid);
    if (svcNames.empty())
    {
        std::cerr << "No mctp D-Bus services found" << std::endl;
        return;
    }
    for (const auto& pair : svcNames)
    {
        const auto& object_path = pair.first;
        const auto& service = pair.second;
        try
        {
            auto method = bus.new_method_call(
                service.c_str(), interfacePath,
                "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
            DbusObjectValueTree objects;
            auto reply = bus.call(method);
            reply.read(objects);
            for (const auto& [path, ifc] : objects)
            {
                if (path == object_path)
                {
                    exploreMctpItem(path, ifc);
                    break;
                }
            }
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            std::cerr << "Failed to retrieve managed objects. Details are "
                      << e.what() << "\n";
        }
    }
}

auto EnumerateEndpoints::exploreMctpItem(
    const sdbusplus::message::object_path& path, const DbusInterfaceMap& ifc)
    -> void
{
    if (const auto eid = getEid(ifc); eid)
    {
        ResponderInfo info{*getEid(ifc), path, getUUID(ifc),
                           getUnixSocketAddress(ifc)};
        respInfos.emplace_back(info);
    }
}

auto EnumerateEndpoints::getEid(const DbusInterfaceMap& interfaces)
    -> std::optional<size_t>
{
    try
    {
        auto intf = interfaces.find(mctpEndpointIntfName);
        if (intf != interfaces.end())
        {
            return getEid(intf->second);
        }
    }
    catch (const std::exception& e)
    {}
    return std::nullopt;
}

auto EnumerateEndpoints::getEid(
    const std::map<std::string, DbusValue>& properties) -> std::optional<size_t>
{
    if (!properties.contains(mctpEndpointIntfPropertyEid))
    {
        return std::nullopt;
    }
    if (!properties.contains(mctpEndpointIntfPropertySupportedMessageTypes))
    {
        return std::nullopt;
    }
    std::optional<size_t> eid;
    try
    {
        eid = std::get<uint32_t>(properties.at(mctpEndpointIntfPropertyEid));
    }
    catch (const std::bad_variant_access& e)
    {
        try
        {
            eid = std::get<size_t>(properties.at(mctpEndpointIntfPropertyEid));
        }
        catch (const std::bad_variant_access& e1)
        {}
    }
    if (eid.has_value())
    {
        try
        {
            const auto& types = std::get<std::vector<uint8_t>>(
                properties.at(mctpEndpointIntfPropertySupportedMessageTypes));
            if (std::find(types.begin(), types.end(), mctpTypeSPDM) !=
                types.end())
            {
                return eid;
            }
        }
        catch (const std::exception& e)
        {}
    }
    return std::nullopt;
}

auto EnumerateEndpoints::getUUID(const DbusInterfaceMap& interfaces)
    -> std::string
{
    try
    {
        auto intf = interfaces.find(uuidIntfName);
        if (intf != interfaces.end())
        {
            const auto& properties = intf->second;
            auto uuid = properties.find(uuidIntfPropertyUUID);
            if (uuid != properties.end())
            {
                try
                {
                    return std::get<std::string>(uuid->second);
                }
                catch (const std::bad_variant_access& e)
                {}
            }
        }
    }
    catch (const std::exception& e)
    {}
    return {};
}

auto EnumerateEndpoints::getUnixSocketAddress(
    const DbusInterfaceMap& interfaces) -> std::string
{
    try
    {
        const auto intf = interfaces.find(mctpUnixSockIntfName);
        if (intf != interfaces.end())
        {
            const auto& properties = intf->second;
            const auto addr = properties.find(unixSocketIntfAddressProperty);
            if (addr != properties.end())
            {
                try
                {
                    const auto& vec =
                        std::get<std::vector<uint8_t>>(addr->second);
                    return {vec.begin(), vec.end()};
                }
                catch (const std::exception& e)
                {}
            }
        }
    }
    catch (const std::exception& e)
    {}
    return {};
}

auto EnumerateEndpoints::getMCTPServices(sdbusplus::bus::bus& bus, int m_eid)
    -> std::vector<std::pair<std::string, std::string>>
{
    static constexpr auto mapperService = "xyz.openbmc_project.ObjectMapper";
    static constexpr auto mapperPath = "/xyz/openbmc_project/object_mapper";
    static constexpr auto mapperInterface = "xyz.openbmc_project.ObjectMapper";
    static constexpr auto method = "GetSubTree";

    std::string path = "/";
    int depth = 0;
    const std::vector<std::string> interfaces = {
        "xyz.openbmc_project.MCTP.Endpoint"};

    std::map<std::string, std::map<std::string, std::vector<std::string>>>
        response;
    std::vector<std::pair<std::string, std::string>> devServices;

    try
    {
        auto reply = bus.new_method_call(mapperService, mapperPath,
                                         mapperInterface, method);
        reply.append(path, depth, interfaces);
        auto dbus_reply = bus.call(reply);
        dbus_reply.read(response);
        bool eidFound = false;
        for (const auto& objectPath : response)
        {
            for (const auto& interface : objectPath.second)
            {
                const auto currEid =
                    getPropertyValue(bus, interface.first, objectPath.first,
                                     "xyz.openbmc_project.MCTP.Endpoint",
                                     mctpEndpointIntfPropertyEid);
                if (m_eid == -1 || (static_cast<size_t>(m_eid) == currEid &&
                                    currEid != invalid_eid))
                {
                    devServices.emplace_back(objectPath.first, interface.first);
                    eidFound = true;
                }
            }
        }
        if (!eidFound)
        {
            std::cerr << "Error: EID " << m_eid
                      << " not found in MCTP endpoints" << std::endl;
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        std::cerr << "Error: Failed to get all bus interfaces" << e.what()
                  << std::endl;
    }
    return devServices;
}

auto EnumerateEndpoints::getPropertyValue(sdbusplus::bus::bus& bus,
                                          const std::string& service,
                                          const std::string& path,
                                          const std::string& interface,
                                          const std::string& property) -> size_t
{
    try
    {
        auto method =
            bus.new_method_call(service.c_str(), path.c_str(),
                                "org.freedesktop.DBus.Properties", "Get");
        method.append(interface);
        method.append(property);
        auto reply = bus.call(method);
        std::variant<uint8_t, uint32_t> rawValue;
        reply.read(rawValue);
        std::optional<std::variant<unsigned char, unsigned int>> value{
            rawValue};
        if (!value)
        {
            return invalid_eid;
        }
        if (auto sizeValue = std::get_if<unsigned char>(&(*value)))
        {
            return *sizeValue;
        }
        else if (auto uintValue = std::get_if<unsigned int>(&(*value)))
        {
            return static_cast<size_t>(*uintValue);
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error while getting the EID" << e.what() << std::endl;
    }
    return invalid_eid;
}

} // namespace spdmt