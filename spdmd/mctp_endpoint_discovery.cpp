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

#include "config.h"

#include "mctp_endpoint_discovery.hpp"

#include "spdmcpp/common.hpp"
#include "spdmd_app_context.hpp"

#include <systemd/sd-daemon.h>

#include <algorithm>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace spdmd
{

constexpr size_t invalidEid = 256;

MctpDiscovery::MctpDiscovery(SpdmdApp& spdmApp) :
    bus(spdmApp.getConn()), spdmApp(spdmApp)
#ifndef DISCOVERY_ONLY_FROM_MCTP_CONTROL
    ,
    inventoryMatch(bus, sdbusplus::bus::match::rules::interfacesAdded("/"),
                   [this](sdbusplus::message::message& msg) {
                       sdbusplus::message::object_path objPath;
                       dbus::InterfaceMap interfaces;
                       msg.read(objPath, interfaces);
                       if (!interfaces.contains(inventorySPDMResponderIntfName))
                       {
                           return;
                       }
                       if (ccsmReady)
                       {
                           inventoryNewObjectSignal(objPath, interfaces);
                       }
                       else
                       {
                           inventorySignalQueue.emplace_back(objPath,
                                                             interfaces);
                       }
                   })
#endif
{
    SPDMCPP_LOG_TRACE_FUNC(spdmApp.getLog());

    initCsmStatus();

    mctpMatch = std::make_unique<sdbusplus::bus::match_t>(
        bus, sdbusplus::bus::match::rules::interfacesAdded(mctpPath),
        [this](sdbusplus::message::message& msg) {
            sdbusplus::message::object_path objPath;
            dbus::InterfaceMap interfaces;
            msg.read(objPath, interfaces);
            using namespace std::chrono_literals;
            if (ccsmReady)
            {
                setupMCTPServices();
                mctpNewObjectSignal(objPath, interfaces);
            }
        });

    ccsmChange = std::make_unique<sdbusplus::bus::match_t>(
        bus,
        sdbusplus::bus::match::rules::propertiesChanged(
            configurableStateManagerMctpPath, csmFeatureReadyStateIntfName),
        [this](sdbusplus::message::message& msg) {
            std::map<std::string, std::variant<std::string>> changedProps;
            std::string iface;
            msg.read(iface, changedProps);
            auto it = changedProps.find("State");
            if (it != changedProps.end())
            {
                const auto& val = std::get<std::string>(it->second);
                ccsmReady = (val == csmFeatureReadyStateEnabled);
                if (ccsmReady)
                {
                    setupMCTPServices();
#ifndef DISCOVERY_ONLY_FROM_MCTP_CONTROL
                    while (!inventorySignalQueue.empty())
                    {
                        const auto& [path, ifc] = inventorySignalQueue.front();
                        inventoryNewObjectSignal(path, ifc);
                        inventorySignalQueue.pop_front();
                    }
#endif
                }
            }
        });
}

void MctpDiscovery::setupMCTPServices()
{
    if (!ccsmReady)
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Debug)
        {
            log.iprintln("Discovery->mctp services are not ready yet..");
        }
        return;
    }

    getMCTPServicesAsync([this](std::unordered_set<std::string> svcNames) {
        if (svcNames.empty())
        {
            if (spdmApp.getLog().logLevel >= LogClass::Level::Error)
            {
                spdmApp.getLog().iprint(
                    "Unable to get interfaces from object mapper");
            }
            return;
        }
        for (const auto& svc : svcNames)
        {
            if (mctpControlServices.count(svc))
            {
                continue;
            }

            mctpControlServices[svc] = std::make_unique<dbus::ServiceHelper>(
                mctpPath, objMgrSvc, svc.c_str());

            auto& conn = spdmApp.getConn();
            conn.async_method_call(
                [this, svc](boost::system::error_code ec,
                            sdbusplus::message::message& replyMsg) {
                    dbus::ObjectValueTree objects;

                    if (ec)
                    {
                        auto& log = spdmApp.getLog();
                        if (log.logLevel >= spdmcpp::LogClass::Level::Error)
                        {
                            log.iprint(
                                "Warning: Discovery->GetManagedObjects error: ");
                            log.iprintln(ec.message());
                        }
                        return;
                    }
                    try
                    {
                        replyMsg.read(objects);
                    }
                    catch (const std::exception& e)
                    {
                        auto& log = spdmApp.getLog();
                        if (log.logLevel >= spdmcpp::LogClass::Level::Error)
                        {
                            log.iprint(
                                "Warning: Discovery->GetManagedObjects parse error: ");
                            log.iprintln(e.what());
                        }
                        return;
                    }

                    for (const auto& [objectPath, interfaces] : objects)
                    {
                        mctpNewObjectSignal(objectPath, interfaces);
                    }
                },
                svc.c_str(), mctpPath, "org.freedesktop.DBus.ObjectManager",
                "GetManagedObjects");
        }
    });
}

void MctpDiscovery::getMCTPServicesAsync(
    std::function<void(std::unordered_set<std::string>)> callback)
{
    static constexpr auto mapperService = "xyz.openbmc_project.ObjectMapper";
    static constexpr auto mapperPath = "/xyz/openbmc_project/object_mapper";
    static constexpr auto mapperInterface = "xyz.openbmc_project.ObjectMapper";
    static constexpr auto method = "GetSubTree";

    std::string rootPath = "/";
    int depth = 0;
    std::vector<std::string> interfaces{"xyz.openbmc_project.MCTP.Endpoint"};

    auto& conn = spdmApp.getConn();

    conn.async_method_call(
        [this, callback =
                   std::move(callback)](boost::system::error_code ec,
                                        sdbusplus::message::message& replyMsg) {
            std::unordered_set<std::string> devServices;

            if (ec)
            {
                auto& log = spdmApp.getLog();
                if (log.logLevel >= spdmcpp::LogClass::Level::Error)
                {
                    log.iprint("getMCTPServicesAsync: D-Bus error: ");
                    log.iprintln(ec.message());
                }
                callback(std::move(devServices));
                return;
            }

            try
            {
                std::map<std::string,
                         std::map<std::string, std::vector<std::string>>>
                    resp;
                replyMsg.read(resp);

                for (const auto& [objPath, serviceMap] : resp)
                {
                    for (const auto& [serviceName, _ifcs] : serviceMap)
                    {
                        devServices.insert(serviceName);
                    }
                }
            }
            catch (const sdbusplus::exception_t& e)
            {
                auto& log = spdmApp.getLog();
                if (log.logLevel >= spdmcpp::LogClass::Level::Error)
                {
                    log.iprint("Failed to parse GetSubTree response: ");
                    log.iprintln(e.what());
                }
            }

            callback(std::move(devServices));
        },
        mapperService, mapperPath, mapperInterface, method,
        rootPath, // Args
        depth, interfaces);
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

    if (!ccsmReady)
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Debug)
        {
            log.iprintln("Discovery->mctp services are not ready yet..");
        }
        return;
    }

    size_t eid = getEid(interfaces);
    if (eid >= invalidEid)
    {
        spdmApp.getLog().iprintln(
            "SPDM mctpNewObjectSignal couldn't get EID for path '" +
            std::string(objPath) + '\'');
        return;
    }

    std::string uuid = getUUID(interfaces);

#ifdef DISCOVERY_ONLY_FROM_MCTP_CONTROL

    sdbusplus::message::object_path invPath;

    if (uuid.empty())
    {
        spdmApp.getLog().iprintln(
            "SPDM mctpNewObjectSignal couldn't get UUID for path '" +
            std::string(objPath) + '\'');
        return;
    }

    auto mediumType = getMediumType(interfaces);
    if (!mediumType)
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {
            log.iprint("Unable to get medium type for EID = ");
            log.iprintln(eid);
        }
        return;
    }

#ifndef MCTP_IN_KERNEL
    auto sockPath = getTransportSocket(interfaces);
    if (sockPath.empty())
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {
            log.iprint("Unable to get transport socket for EID = ");
            log.iprintln(eid);
        }
        return;
    }
    tryConnectMCTP(sockPath);
#else
    auto sockPath = "";
#endif
    dbus_api::ResponderArgs args{
        static_cast<uint8_t>(eid), uuid,
        mediumType.value(),        objPath,
        std::move(invPath),        std::move(sockPath)};
    spdmApp.discoveryUpdateResponder(args);

#else // DISCOVERY_ONLY_FROM_MCTP_CONTROL not defined

    if (uuid.empty())
    {
        spdmApp.getLog().iprintln(
            "SPDM mctpNewObjectSignal couldn't get UUID for path '" +
            std::string(objPath) + '\'');
        return;
    }

    auto mediumType = getMediumType(interfaces);
    if (!mediumType)
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {
            log.iprint("Unable to get medium type for EID = ");
            log.iprint(eid);
        }
        return;
    }
#ifndef MCTP_IN_KERNEL
    auto sockPath = getTransportSocket(interfaces);
    if (sockPath.empty())
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {
            log.iprint("Unable to get transport socket for EID = ");
            log.iprint(eid);
        }
        return;
    }
#else
    std::string sockPath = "";
#endif
    getInventoryPathAsync(uuid, [this, eid, uuid, objPath, mediumType,
                                 sockPath](
                                    sdbusplus::message::object_path invPath) {
        if (invPath.filename().empty())
        {
            static constexpr auto confName = "name";
            auto eidName =
                spdmApp.getPropertyByEid<const std::string>(eid, confName);
            if (!eidName.has_value())
            {
                spdmApp.getLog().iprintln(
                    "SPDM mctpNewObjectSignal couldn't get inventory path for UUID '" +
                    uuid + "' EID " + std::to_string(eid));
                return;
            }
            // if found in config, build the path
            invPath = "/" + eidName.value();
        }

#ifndef MCTP_IN_KERNEL
        tryConnectMCTP(sockPath);
#endif
        // Then create the Responder
        dbus_api::ResponderArgs args{
            static_cast<uint8_t>(eid), uuid,
            mediumType.value(),        objPath,
            std::move(invPath),        std::move(sockPath)};
        spdmApp.discoveryUpdateResponder(args);
    });

#endif // DISCOVERY_ONLY_FROM_MCTP_CONTROL
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
        spdmApp.getLog().iprintln(
            "SPDM inventoryNewObjectSignal couldn't get UUID for path '" +
            std::string(objPath) + '\'');
        return;
    }

    getMCTPObjectAsync(uuid, [this, objPath, uuid](Object mctpObj) {
        if (!mctpObj.isValid())
        {
            spdmApp.getLog().iprintln(
                "SPDM inventoryNewObjectSignal couldn't get EID for UUID '" +
                uuid + '\'');
            return;
        }

        size_t eid = getEid(mctpObj.interfaces);
        if (eid == invalidEid)
        {
            spdmApp.getLog().iprintln(
                "SPDM inventoryNewObjectSignal couldn't get EID for UUID '" +
                uuid + '\'');
            return;
        }

        auto mediumType = getMediumType(mctpObj.interfaces);
        if (!mediumType)
        {
            auto& log = spdmApp.getLog();
            if (log.logLevel >= LogClass::Level::Error)
            {
                log.iprint("Unable to get medium type for ");
                log.iprint(" EID = ");
                log.iprint(eid);
                log.iprint(" UUID = ");
                log.iprintln(uuid);
            }
            return;
        }
#ifndef MCTP_IN_KERNEL
        auto transpSock = getTransportSocket(mctpObj.interfaces);
        if (transpSock.empty())
        {
            auto& log = spdmApp.getLog();
            if (log.logLevel >= LogClass::Level::Error)
            {
                log.iprint("Unable to get transport socket for ");
                log.iprint(" EID = ");
                log.iprint(eid);
                log.iprint(" UUID = ");
                log.iprint(uuid);
                log.iprint(" PATH = ");
                log.iprintln(mctpObj.path.str);
            }
            return;
        }

        tryConnectMCTP(transpSock);
#else
        std::string transpSock = "";
#endif
        // Pass to the responder
        dbus_api::ResponderArgs args{static_cast<uint8_t>(eid),
                                     uuid,
                                     mediumType.value(),
                                     mctpObj.path,
                                     objPath,
                                     std::move(transpSock)};
        spdmApp.discoveryUpdateResponder(args);
    });
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

std::string
    MctpDiscovery::getTransportSocket(const dbus::InterfaceMap& interfaces)
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
                    const auto& vec =
                        std::get<std::vector<uint8_t>>(addr->second);
                    return {vec.begin(), vec.end()};
                }
                catch (const std::exception& e)
                {
                    if (spdmApp.getLog().logLevel >=
                        spdmcpp::LogClass::Level::Error)
                    {
                        using namespace std::string_literals;
                        spdmApp.getLog().iprintln(
                            "Unable to get transport socket property "s +
                            e.what());
                    }
                }
            }
        }
    }
    catch (const std::exception& e)
    {
        if (spdmApp.getLog().logLevel >= spdmcpp::LogClass::Level::Error)
        {
            using namespace std::string_literals;
            spdmApp.getLog().iprintln(
                "Unable to get transport socket inteface "s + e.what());
        }
    }
    return {};
}

std::string MctpDiscovery::getUUID(const dbus::InterfaceMap& interfaces)
{
    SPDMCPP_LOG_TRACE_FUNC(spdmApp.getLog());

    try
    {
        auto intf = interfaces.find(mctpUUIDIntfName);
        if (intf == interfaces.end())
        {
            intf = interfaces.find(uuidIntfName);
        }
        if (intf != interfaces.end())
        {
            const auto& properties = intf->second;
            auto uuid = properties.find(uuidIntfPropertyUUID);
            if (uuid != properties.end())
            {
                return std::get<std::string>(uuid->second);
            }
            if (spdmApp.getLog().logLevel >= LogClass::Level::Error)
            {
                spdmApp.getLog().iprint("UUID interface was not found for: ");
                spdmApp.getLog().iprintln(intf->first);
            }
        }
    }
    catch (const std::exception& e)
    {
        spdmApp.getLog().print(e.what());
    }
    return {};
}

void MctpDiscovery::getPropertyValueAsync(
    const std::string& service, const std::string& path,
    const std::string& interface, const std::string& property,
    std::function<void(std::string)> callback)
{
    auto& conn = spdmApp.getConn();

    conn.async_method_call(
        [this, callback =
                   std::move(callback)](boost::system::error_code ec,
                                        sdbusplus::message::message& replyMsg) {
            std::string result;
            if (ec)
            {
                auto& log = spdmApp.getLog();
                if (log.logLevel >= spdmcpp::LogClass::Level::Error)
                {
                    log.iprint("getPropertyValueAsync: dbus error: ");
                    log.iprintln(ec.message());
                }
                callback(std::move(result));
                return;
            }

            try
            {
                std::variant<std::string> val;
                replyMsg.read(val);
                result = std::get<std::string>(val);
            }
            catch (const std::exception& e)
            {
                auto& log = spdmApp.getLog();
                if (log.logLevel >= spdmcpp::LogClass::Level::Error)
                {
                    log.iprint("getPropertyValueAsync parse error: ");
                    log.iprintln(e.what());
                }
            }

            callback(std::move(result));
        },
        service.c_str(), path.c_str(), "org.freedesktop.DBus.Properties", "Get",
        interface, property);
}

void MctpDiscovery::getMCTPObjectAsync(const std::string& uuid,
                                       std::function<void(Object)> callback)
{
    if (mctpControlServices.empty())
    {
        callback(Object{});
        return;
    }

    auto sharedCount = std::make_shared<std::atomic<size_t>>(0);
    auto total = mctpControlServices.size();
    auto found = std::make_shared<std::atomic<bool>>(false);

    for (auto& [svcName, service] : mctpControlServices)
    {
        auto& conn = spdmApp.getConn();
        conn.async_method_call(
            [this, svcName, uuid, callback, sharedCount, total,
             found](boost::system::error_code ec,
                    sdbusplus::message::message& msg) {
                if (*found)
                {
                    return;
                }
                if (ec)
                {
                    auto x = ++(*sharedCount);
                    if (x == total && !*found)
                    {
                        callback(Object{});
                    }
                    return;
                }

                dbus::ObjectValueTree objTree;
                try
                {
                    msg.read(objTree);
                }
                catch (const std::exception& e)
                {
                    auto x = ++(*sharedCount);
                    if (x == total && !*found)
                    {
                        callback(Object{});
                    }
                    return;
                }

                for (const auto& [objectPath, interfaces] : objTree)
                {
                    std::string discoveredUuid = getUUID(interfaces);
                    if (discoveredUuid == uuid)
                    {
                        *found = true;
                        Object obj{objectPath, interfaces};
                        callback(std::move(obj));
                        return;
                    }
                }
                auto x = ++(*sharedCount);
                if (x == total && !*found)
                {
                    callback(Object{});
                }
            },
            svcName.c_str(), mctpPath, "org.freedesktop.DBus.ObjectManager",
            "GetManagedObjects");
    }
}

void MctpDiscovery::getInventoryPathAsync(
    const std::string& uuid,
    std::function<void(sdbusplus::message::object_path)> callback)
{
    SPDMCPP_LOG_TRACE_FUNC(spdmApp.getLog());

    // Same constants as before
    static constexpr auto mapperService = "xyz.openbmc_project.ObjectMapper";
    static constexpr auto mapperPath = "/xyz/openbmc_project/object_mapper";
    static constexpr auto mapperInterface = "xyz.openbmc_project.ObjectMapper";
    static constexpr auto method = "GetSubTree";

    std::string rootPath = "/";
    int depth = 0;
    std::vector<std::string> ifaces{
        "xyz.openbmc_project.Inventory.Item.SPDMResponder"};

    auto& conn = spdmApp.getConn();
    conn.async_method_call(
        [this, uuid, callback = std::move(callback)](
            boost::system::error_code ec,
            sdbusplus::message::message& replyMsg) {
            auto resultPathPtr =
                std::make_shared<sdbusplus::message::object_path>();

            if (ec)
            {
                auto& log = spdmApp.getLog();
                if (log.logLevel >= spdmcpp::LogClass::Level::Error)
                {
                    log.iprint("getInventoryPathAsync: D-Bus error: ");
                    log.iprintln(ec.message());
                }
                callback(*resultPathPtr);
                return;
            }

            std::map<std::string, std::map<std::string, std::set<std::string>>>
                response;
            try
            {
                replyMsg.read(response);
            }
            catch (const std::exception& e)
            {
                auto& log = spdmApp.getLog();
                if (log.logLevel >= spdmcpp::LogClass::Level::Error)
                {
                    log.iprint("getInventoryPathAsync parse error: ");
                    log.iprintln(e.what());
                }
                callback(*resultPathPtr);
                return;
            }

            struct Candidate
            {
                std::string objectPath;
                std::string serviceName;
                std::string interfaceName;
            };
            auto candidates = std::make_shared<std::vector<Candidate>>();

            for (const auto& [objPath, serviceMap] : response)
            {
                for (const auto& [serviceName, interfaceSet] : serviceMap)
                {
                    auto foundMctp = interfaceSet.find(mctpUUIDIntfName);
                    auto foundUuid = interfaceSet.find(uuidIntfName);

                    if (foundMctp != interfaceSet.end())
                    {
                        candidates->push_back(
                            {objPath, serviceName, mctpUUIDIntfName});
                    }
                    else if (foundUuid != interfaceSet.end())
                    {
                        candidates->push_back(
                            {objPath, serviceName, uuidIntfName});
                    }
                    else
                    {
                        auto& log = spdmApp.getLog();
                        if (log.logLevel >= LogClass::Level::Error)
                        {
                            log.iprint("UUID interface was not found for: ");
                            log.iprintln(objPath);
                        }
                    }
                }
            }

            if (candidates->empty())
            {
                callback(*resultPathPtr);
                return;
            }

            auto sharedIndex = std::make_shared<size_t>(0);
            auto processNextPtr = std::make_shared<std::function<void()>>();

            *processNextPtr = [this, uuid, callback, candidates, sharedIndex,
                               resultPathPtr, processNextPtr]() {
                if (*sharedIndex >= candidates->size())
                {
                    callback(*resultPathPtr);
                    return;
                }

                const auto& c = (*candidates)[*sharedIndex];
                getPropertyValueAsync(
                    c.serviceName, c.objectPath, c.interfaceName,
                    uuidIntfPropertyUUID,
                    [uuid, callback, candidates, sharedIndex, resultPathPtr,
                     processNextPtr](std::string propertyVal) mutable {
                        if (uuid == propertyVal)
                        {
                            *resultPathPtr = sdbusplus::message::object_path(
                                (*candidates)[*sharedIndex].objectPath);
                            callback(*resultPathPtr);
                            return;
                        }
                        else
                        {
                            ++(*sharedIndex);
                            (*processNextPtr)();
                        }
                    });
            };

            (*processNextPtr)();
        },
        mapperService, mapperPath, mapperInterface, method, rootPath, depth,
        ifaces);
}

std::optional<spdmcpp::TransportMedium>
    MctpDiscovery::getMediumType(const dbus::InterfaceMap& interfaces)
{
    try
    {
        auto intf = interfaces.find(mctpBindingIntfProperty);
        if (intf != interfaces.end())
        {
            return getInternalMediumType(intf->second,
                                         mctpBindingIntfPropertyBindType);
        }
        intf = interfaces.find(mctpEndpointIntfName);
        if (intf != interfaces.end())
        {
            return getInternalMediumType(intf->second,
                                         mctpEndpointIntfPropertyMediumType);
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
            for (const auto& [path, _] : interfaces)
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
        mediumTypeStr =
            std::get<std::string>(properties.at(std::string(propName)));
        mediumTypeStr =
            mediumTypeStr.substr(mediumTypeStr.find_last_of('.') + 1);
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
            log.iprintln(std::move(mediumTypeStr));
        }
    }
    return std::nullopt;
}

void MctpDiscovery::initCsmStatus()
{
    using error_code_t = boost::system::error_code;
    auto& conn = spdmApp.getConn();
    auto handler = [this](error_code_t ec,
                          const std::variant<std::string>& val) {
        if (ec)
        {
            auto& log = spdmApp.getLog();
            if (log.logLevel >= spdmcpp::LogClass::Level::Error)
            {
                log.iprintln("initCsmStatus() failed: " + ec.message());
            }
            ccsmReady = false;
            return;
        }
        ccsmReady = (std::get<std::string>(val) == csmFeatureReadyStateEnabled);
        if (ccsmReady)
        {
            setupMCTPServices();
#ifndef DISCOVERY_ONLY_FROM_MCTP_CONTROL
            while (!inventorySignalQueue.empty())
            {
                const auto& [path, ifc] = inventorySignalQueue.front();
                inventoryNewObjectSignal(path, ifc);
                inventorySignalQueue.pop_front();
            }
#endif
        }
    };

    conn.async_method_call(
        [handler](const boost::system::error_code& error,
                  std::variant<std::string> stateVal) {
            handler(error, stateVal);
        },
        configurableStateManagerService, configurableStateManagerMctpPath,
        "org.freedesktop.DBus.Properties", "Get", csmFeatureReadyStateIntfName,
        "State");
}

} // namespace spdmd
