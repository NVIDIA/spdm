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
#include "mctp_endpoint_discovery.hpp"
#include "spdmcpp/common.hpp"
#include "spdmd_app_context.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace spdmd
{

constexpr size_t invalidEid = 256;

MctpDiscovery::MctpDiscovery(SpdmdApp& spdmApp) :
    bus(spdmApp.getBus()), spdmApp(spdmApp)
#ifndef DISCOVERY_ONLY_FROM_MCTP_CONTROL
    ,inventoryMatch(spdmApp.getBus(),
        sdbusplus::bus::match::rules::interfacesAdded(
            inventoryService.getPath()
        ),
        [this](sdbusplus::message::message& msg) {
            sdbusplus::message::object_path objPath;
            dbus::InterfaceMap interfaces;
            msg.read(objPath, interfaces);
            inventoryNewObjectSignal(objPath, interfaces);
        })
#endif
{
    SPDMCPP_LOG_TRACE_FUNC(spdmApp.getLog());

    auto svcNames = getMCTPServices();
    if (svcNames.empty())
    {
        if (spdmApp.getLog().logLevel >= LogClass::Level::Error)
        {
            spdmApp.getLog().iprint("Unable to get interfaces from object mapper");
        }
    }
    for (const auto& svc : svcNames)
    {
        mctpControlServices.emplace_back(
            std::make_unique<dbus::ServiceHelper>(mctpPath, objMgrSvc, svc.c_str())
        );
        mctpMatch.emplace_back(
            std::make_unique<sdbusplus::bus::match_t>(
                spdmApp.getBus(),
                sdbusplus::bus::match::rules::interfacesAdded(
                    mctpControlServices.back()->getPath()
                ),
                [this](sdbusplus::message::message& msg) {
                    sdbusplus::message::object_path objPath;
                    dbus::InterfaceMap interfaces;
                    msg.read(objPath, interfaces);
                    mctpNewObjectSignal(objPath, interfaces);
                }
            )
        );
        dbus::ObjectValueTree objects;
        try {
            auto method = mctpControlServices.back()->new_method_call(bus, "GetManagedObjects");
            auto reply = bus.call(method);
            reply.read(objects);
        }
        catch (const std::exception& e)
        {
            using namespace std::string_literals;
            spdmApp.getLog().iprintln("Warning: Discovery->GetManagedObjects "s + e.what());
            continue;
        }
        for (const auto& [objectPath, interfaces] : objects)
        {
            mctpNewObjectSignal(objectPath, interfaces);
        }
    }
}


std::unordered_set<std::string> MctpDiscovery::getMCTPServices()
{
    static constexpr auto mapperService = "xyz.openbmc_project.ObjectMapper";
    static constexpr auto mapperPath = "/xyz/openbmc_project/object_mapper";
    static constexpr auto mapperInterface = "xyz.openbmc_project.ObjectMapper";
    static constexpr auto method = "GetSubTree";

    std::string path = "/";
    int depth = 0;
    const std::vector<std::string> interfaces = {"xyz.openbmc_project.MCTP.Endpoint"};

    auto reply = bus.new_method_call(mapperService, mapperPath, mapperInterface, method);
    reply.append(path, depth, interfaces);

    std::map<std::string, std::map<std::string, std::vector<std::string>>> response;
    std::unordered_set<std::string> devServices;

    try
    {
        bus.call(reply).read(response);
        for (const auto& objectPath : response)
        {
            for (const auto& interface : objectPath.second)
            {
                devServices.insert(interface.first);
            }
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        if (spdmApp.getLog().logLevel >= LogClass::Level::Error)
        {
            spdmApp.getLog().iprint("Failed to get all bus interfaces: ");
            spdmApp.getLog().iprintln(e.what());
        }
    }
    return devServices;
}


void MctpDiscovery::tryConnectMCTP(const std::string& sockPath)
{
    // There is some issue with MCTP-PCIE CTRL daemon which starts,so
    // SPDM service gets started and after a moment MCTP daemon fails which is
    // causing the SPDM daemon to fail when it tries to connect the MCTP daemon
    // through the unix socket.
    try
    {
        spdmApp.connectMCTP(sockPath);
    }
    catch (const std::exception& e)
    {
        std::cerr << "exception occured during MCTP connect '" << e.what()
                  << std::endl;
        throw; // let the application crash
    }
}

void MctpDiscovery::mctpNewObjectSignal(
    const sdbusplus::message::object_path& objPath,
    const dbus::InterfaceMap& interfaces)
{
    spdmApp.getLog().iprintln("mctpNewObjectSignal: " + std::string(objPath));

    size_t eid = getEid(interfaces);
    if (eid == invalidEid)
    {
        spdmApp.getLog().iprintln("SPDM mctpNewObjectSignal couldn't get EID for path '"s + std::string(objPath) + '\'');
        return;
    }
    auto uuid = getUUID(interfaces);
#ifdef DISCOVERY_ONLY_FROM_MCTP_CONTROL
    sdbusplus::message::object_path invPath;
#else
    if (uuid.empty()) {
        spdmApp.getLog().iprintln("SPDM mctpNewObjectSignal couldn't get UUID for path '"s + std::string(objPath) + '\'');
        return;
    }
    auto invPath = getInventoryPath(uuid);
    if (invPath.filename().empty()) {
        static constexpr auto confName = "name";
        const auto eidName = spdmApp.getPropertyByEid<const std::string>(eid, confName);
        if(!eidName.has_value()) {
            spdmApp.getLog().iprintln("SPDM mctpNewObjectSignal couldn't get inventory path for UUID'"s
                + uuid + " EID " + std::to_string(eid) );
            return;
        }
        invPath = "/" + eidName.value();
    }
#endif
    auto mediumType = getMediumType(interfaces);
    if (!mediumType)
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {
            log.iprint("Unable to get medium type for");
            log.iprint(" EID = ");
            log.iprint(eid);
            log.iprint(" UUID = ");
            log.iprint(uuid);
            log.iprint(" PATH = ");
            log.iprint(objPath.str);
            log.iprint(" INVPATH = ");
            log.iprintln(invPath.str);
        }
        return;
    }
    auto sockPath = getTransportSocket(interfaces);
    if (sockPath.empty())
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {
            log.iprint("Unable to get transport socket for");
            log.iprint(" EID = ");
            log.iprint(eid);
            log.iprint(" UUID = ");
            log.iprint(uuid);
            log.iprint(" PATH = ");
            log.iprint(objPath.str);
            log.iprint(" INVPATH = ");
            log.iprintln(invPath.str);
        }
        return;
    }
    tryConnectMCTP(sockPath);
    dbus_api::ResponderArgs args { mctp_eid_t(eid), uuid, mediumType, objPath, invPath, sockPath };
    spdmApp.discoveryUpdateResponder(args);
}

#ifndef DISCOVERY_ONLY_FROM_MCTP_CONTROL
void MctpDiscovery::inventoryNewObjectSignal(
    const sdbusplus::message::object_path& objPath,
    const dbus::InterfaceMap& interfaces)
{
    if (!interfaces.contains(inventorySPDMResponderIntfName))
    {
        return;
    }
    auto uuid = getUUID(interfaces);
    if (uuid.empty())
    {
        spdmApp.getLog().iprintln("SPDM inventoryNewObjectSignal couldn't get UUID for path '"s + std::string(objPath) + '\'');
        return;
    }
    auto mctp = getMCTPObject(uuid);
    size_t eid = getEid(mctp.interfaces);
    if (eid == invalidEid)
    {
        spdmApp.getLog().iprintln("SPDM inventoryNewObjectSignal couldn't get EID for UUID '"s + uuid + '\'');
        return;
    }
    auto mediumType = getMediumType(mctp.interfaces);

    if (!mediumType)
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {
            log.iprint("Unable to get medium type for");
            log.iprint(" EID = ");
            log.iprint(eid);
            log.iprint(" UUID = ");
            log.iprint(uuid);
            log.iprint(" MCTPPATH = ");
            log.iprint(mctp.path.str);
            log.iprint(" PATH = ");
            log.iprintln(objPath.str);
        }
        return;
    }

    const auto transpSock = getTransportSocket(mctp.interfaces);
    if (transpSock.empty())
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {
            log.iprint("Unable to get transport socket for");
            log.iprint(" EID = ");
            log.iprint(eid);
            log.iprint(" UUID = ");
            log.iprint(uuid);
            log.iprint(" MCTPPATH = ");
            log.iprint(mctp.path.str);
            log.iprint(" PATH = ");
            log.iprintln(objPath.str);
        }
        return;
    }
    tryConnectMCTP(transpSock);
    dbus_api::ResponderArgs args { mctp_eid_t(eid), uuid, mediumType, mctp.path, objPath, transpSock };
    spdmApp.discoveryUpdateResponder(args);
}
#endif

size_t MctpDiscovery::getEid(const dbus::InterfaceMap& interfaces)
{
    SPDMCPP_LOG_TRACE_FUNC(spdmApp.getLog());

    try
    {
        auto intf = interfaces.find(mctpEndpointIntfName);
        if (intf != interfaces.end())
        {
            return getEid(intf->second);
        }
    }
    catch (const std::exception& e)
    {
        spdmApp.getLog().println(e.what());
    }
    return invalidEid;
}

size_t
    MctpDiscovery::getEid(const std::map<std::string, dbus::Value>& properties)
{

    SPDMCPP_LOG_TRACE_FUNC(spdmApp.getLog());

    if (!properties.contains(mctpEndpointIntfPropertyEid))
    {
        return invalidEid;
    }
    if (!properties.contains(mctpEndpointIntfPropertySupportedMessageTypes))
    {
        return invalidEid;
    }

    size_t eid = invalidEid;
    /* Type of EID property depends on the system,
     *  so checking of all possible types is mandatory */
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
        {
            spdmApp.getLog().println(e1.what());
        }
    }
    if (eid < invalidEid)
    {
        try
        {
            auto types = std::get<std::vector<uint8_t>>(
                properties.at(mctpEndpointIntfPropertySupportedMessageTypes));
            if (std::find(types.begin(), types.end(), mctpTypeSPDM) !=
                types.end())
            {
                return eid;
            }
        }
        catch (const std::exception& e)
        {
            spdmApp.getLog().print(e.what());
        }
    }

    return invalidEid;
}

std::string MctpDiscovery::getTransportSocket(const dbus::InterfaceMap& interfaces)
{
    SPDMCPP_LOG_TRACE_FUNC(spdmApp.getLog());
    try
    {
        const auto intf = interfaces.find(mctpTransportSockIntfName);
        if (intf != interfaces.end())
        {
            const auto& properties = intf->second;
            const auto addr = properties.find(mctpTransportSockIntfType);
            if (addr != properties.end())
            {
                try
                {
                    const auto vec = std::get<std::vector<uint8_t>>(addr->second);
                    return {vec.begin(), vec.end()};
                }
                catch(const std::exception& e)
                {
                    if (spdmApp.getLog().logLevel >= spdmcpp::LogClass::Level::Error)
                    {
                        using namespace std::string_literals;
                        spdmApp.getLog().iprintln("Unable to get transport socket property "s + e.what());
                    }
                }
            }
        }
    }
    catch(const std::exception& e)
    {
        if (spdmApp.getLog().logLevel >= spdmcpp::LogClass::Level::Error)
        {
            using namespace std::string_literals;
            spdmApp.getLog().iprintln("Unable to get transport socket inteface "s + e.what());
        }
    }
    return {};
}

std::string MctpDiscovery::getUUID(const dbus::InterfaceMap& interfaces)
{
    SPDMCPP_LOG_TRACE_FUNC(spdmApp.getLog());

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
                {
                    spdmApp.getLog().println(e.what());
                }
            }
        }
    }
    catch (const std::exception& e)
    {
        spdmApp.getLog().print(e.what());
    }
    return {};
}

MctpDiscovery::Object MctpDiscovery::getMCTPObject(const std::string& uuid)
{

    dbus::ObjectValueTree objects;

    SPDMCPP_LOG_TRACE_FUNC(spdmApp.getLog());

    try
    {
        for (auto &service: mctpControlServices)
        {
            auto method =
                service->new_method_call(bus, "GetManagedObjects");
            auto reply = bus.call(method);
            reply.read(objects);

            for (const auto& [objectPath, interfaces] : objects)
            {
                if (uuid == getUUID(interfaces))
                {
                    return {objectPath, interfaces};
                }
            }
        }
    }
    catch (const std::exception& e)
    {
        spdmApp.getLog().print(e.what());
    }
    return {};

}


sdbusplus::message::object_path
    MctpDiscovery::getInventoryPath(const std::string& uuid)
{
    dbus::ObjectValueTree objects;

    SPDMCPP_LOG_TRACE_FUNC(spdmApp.getLog());

    // TODO couldn't test/verify so this is most likely invalid/broken
    try
    {
        auto method =
            inventoryService.new_method_call(bus, "GetManagedObjects");
        auto reply = bus.call(method);
        reply.read(objects);

        for (const auto& [objectPath, interfaces] : objects)
        {
            if (interfaces.contains(inventorySPDMResponderIntfName))
            {
                auto id = getUUID(interfaces);
                if (id == uuid)
                {
                    return objectPath;
                }
            }
        }
    }
    catch (const std::exception& e)
    {
        spdmApp.getLog().print(e.what());
    }
    return {};
}

std::optional<spdmcpp::TransportMedium> MctpDiscovery::getMediumType(const dbus::InterfaceMap& interfaces)
{
    try
    {
        auto intf = interfaces.find(mctpBindingIntfProperty);
        if(intf != interfaces.end())
        {
            return getInternalMediumType(intf->second, mctpBindingIntfPropertyBindType);
        }
        intf = interfaces.find(mctpEndpointIntfName);
        if (intf != interfaces.end())
        {
            return getInternalMediumType(intf->second, mctpEndpointIntfPropertyMediumType);
        }
    }
    catch (const std::exception& e)
    {
        spdmApp.getLog().print(e.what());
    }
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {
            log.println("Unable to determine medium type. Interfaces path:");
            for (const auto& [path,_] : interfaces)
            {
                log.println(path);
            }
        }
    }
    return std::nullopt;
}

std::optional<spdmcpp::TransportMedium> MctpDiscovery::getInternalMediumType(
    const std::map<std::string, dbus::Value>& properties,
    std::string_view propName)
{
    if (!properties.contains(std::string(propName)))
    {
        return spdmcpp::TransportMedium::PCIe;
    }
    std::string mediumTypeStr;

    try
    {
        mediumTypeStr = std::get<std::string>(properties.at(std::string(propName)));
        mediumTypeStr = mediumTypeStr.substr(mediumTypeStr.find_last_of('.')+1);
    }
    catch (const std::exception& e)
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {
            log.iprint("Property get exception for: ");
            log.iprint(std::string(propName));
            log.iprint(" what: ");
            log.iprintln(e.what());
        }
        return std::nullopt;
    }
    if (mediumTypeStr == "PCIe")
    {
        return spdmcpp::TransportMedium::PCIe;
    }
    if (mediumTypeStr == "SPI")
    {
        return spdmcpp::TransportMedium::SPI;
    }
    if (mediumTypeStr == "SMBus")
    {
        return spdmcpp::TransportMedium::I2C;
    }
    if (mediumTypeStr == "USB")
    {
        return spdmcpp::TransportMedium::USB;
    }
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {
            log.iprint("Unknown transport medium string: ");
            log.iprintln(mediumTypeStr);
        }
    }
    return std::nullopt;
}

} // namespace spdmd
