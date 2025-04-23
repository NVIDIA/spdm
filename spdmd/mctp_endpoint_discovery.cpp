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
/* There is a difference between the data type in ctrl
   daemon and code construct eid data type.
 */
constexpr std::variant<uint32_t, uint8_t> invalidEid = uint8_t(0xFF);

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
#ifndef CSM_SERVICE_ENABLED
                       ccsmReady = true;
#endif
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
#ifdef CSM_SERVICE_ENABLED
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
#endif
}

void MctpDiscovery::setupMCTPServices()
{
#ifndef MCTP_IN_KERNEL
    if (!ccsmReady)
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Debug)
        {
            log.iprintln("Discovery->mctp services are not ready yet..");
        }
        return;
    }
#endif
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
    /** If MCTP service is not read yet ignore */
#ifndef MCTP_IN_KERNEL
    if (!ccsmReady)
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Debug)
        {
            log.iprintln("Discovery->mctp services are not ready yet..");
        }
        return;
    }
#endif
    auto eid = getEid(interfaces);
    std::string eidstrValue = "";
    uint8_t eidValue1 = 0;
    if (eid.has_value())
    {
        auto eidValue = eid.value();
        if (std::holds_alternative<unsigned char>(eidValue))
        {
            eidstrValue = std::to_string(std::get<unsigned char>(eidValue));
            eidValue1 = std::get<unsigned char>(eidValue);
        }
        else if (std::holds_alternative<unsigned int>(eidValue))
        {
            eidstrValue = std::to_string(std::get<unsigned int>(eidValue));
            eidValue1 = std::get<unsigned int>(eidValue);
        }
    }
    if (eid >= invalidEid)
    {
        spdmApp.getLog().iprintln(
            "SPDM mctpNewObjectSignal couldn't get EID for path '" +
            std::string(objPath) + '\'');
        return;
    }

    std::string uuid = getUUID(interfaces);

#ifdef DISCOVERY_ONLY_FROM_MCTP_CONTROL
#ifndef MCTP_IN_KERNEL
    auto mediumType = getMediumType(interfaces);
    if (mediumType.empty())
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {
            log.iprint("Unable to get medium type for EID = ");
            log.iprintln(eidValue1);
        }
        return;
    }

    // Get the binding type from the interfaces
    auto bindingType = getBindingType(interfaces);
    if (bindingType.empty())
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {
            log.iprint("Unable to get binding type for EID = ");
            log.iprintln(eid);
        }
        return;
    }

    auto sockPath = getTransportSocket(interfaces);
    if (sockPath.empty())
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {
            log.iprint("Unable to get transport socket for EID = ");
            log.iprintln(eidValue1);
        }
        return;
    }
    tryConnectMCTP(sockPath);
#else
    auto sockPath = "";
    auto mediumType = "";
    auto bindingType = "";
#endif
    dbus_api::ResponderArgs args{};
    if (eid.has_value())
    {
        auto value = eid.value();

        if (std::holds_alternative<unsigned char>(value))
        {
            args = dbus_api::ResponderArgs{std::get<unsigned char>(value),
                                           uuid,
                                           mediumType,
                                           bindingType,
                                           objPath,
                                           std::move(invPath),
                                           std::move(sockPath)};
        }
        else if (std::holds_alternative<unsigned int>(value))
        {
            args = dbus_api::ResponderArgs{
                static_cast<unsigned char>(std::get<unsigned int>(value)),
                uuid,
                mediumType,
                bindingType,
                objPath,
                std::move(invPath),
                std::move(sockPath)};
        }
        spdmApp.discoveryUpdateResponder(args);
    }

#else // DISCOVERY_ONLY_FROM_MCTP_CONTROL not defined

    if (uuid.empty())
    {
        spdmApp.getLog().iprintln(
            "SPDM mctpNewObjectSignal couldn't get UUID for path '" +
            std::string(objPath) + '\'');
        return;
    }
#ifndef MCTP_IN_KERNEL
    auto mediumType = getMediumType(interfaces);
    if (mediumType.empty())
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {
            log.iprint("Unable to get medium type for EID = ");
            log.iprint(eidValue1);
        }
        return;
    }

    // Get the binding type from the interfaces
    auto bindingType = getBindingType(interfaces);
    if (bindingType.empty())
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {
            log.iprint("Unable to get binding type for EID = ");
            log.iprintln(eid);
        }
        return;
    }

    auto sockPath = getTransportSocket(interfaces);
    if (sockPath.empty())
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {

            log.iprint("Unable to get transport socket for EID = ");
            log.iprint(eidValue1);
        }
        return;
    }
#else
    auto sockPath = "";
    auto mediumType = "";
    auto bindingType = "";
#endif
    getInventoryPathAsync(uuid, [this, eid, uuid, objPath, mediumType,
                                 bindingType, sockPath, eidValue1](
                                    sdbusplus::message::object_path invPath) {
        if (invPath.filename().empty())
        {
            static constexpr auto confName = "name";
            auto eidName = spdmApp.getPropertyByEid<const std::string>(
                eidValue1, confName);
            if (!eidName.has_value())
            {
                spdmApp.getLog().iprintln(
                    "SPDM mctpNewObjectSignal couldn't get inventory path for UUID '" +
                    uuid + "' EID " + std::to_string(eidValue1));
                return;
            }
            // if found in config, build the path
            invPath = "/" + eidName.value();
        }

#ifndef MCTP_IN_KERNEL
        tryConnectMCTP(sockPath);
#endif
        // Then create the Responder
        dbus_api::ResponderArgs args{};
        if (eid.has_value())
        {
            auto value = eid.value();

            if (std::holds_alternative<unsigned char>(value))
            {
                args = dbus_api::ResponderArgs{std::get<unsigned char>(value),
                                               uuid,
                                               mediumType,
                                               bindingType,
                                               objPath,
                                               std::move(invPath),
                                               std::move(sockPath)};
            }
            else if (std::holds_alternative<unsigned int>(value))
            {
                args = dbus_api::ResponderArgs{
                    static_cast<unsigned char>(std::get<unsigned int>(value)),
                    uuid,
                    mediumType,
                    bindingType,
                    objPath,
                    std::move(invPath),
                    std::move(sockPath)};
            }
            spdmApp.discoveryUpdateResponder(args);
        }
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
        std::string eidstrValue = "";
        EidType eid = getEid(mctpObj.interfaces);
        if (eid.has_value())
        {
            auto eidValue = eid.value();

            if (std::holds_alternative<unsigned char>(eidValue))
            {
                eidstrValue = std::to_string(std::get<unsigned char>(eidValue));
            }
            else if (std::holds_alternative<unsigned int>(eidValue))
            {
                eidstrValue = std::to_string(std::get<unsigned int>(eidValue));
            }
        }
        if (eid == invalidEid)
        {
            spdmApp.getLog().iprintln(
                "SPDM inventoryNewObjectSignal couldn't get EID for UUID '"s +
                uuid + '\'');
            return;
        }

#ifndef MCTP_IN_KERNEL
        auto mediumType = getMediumType(mctpObj.interfaces);
        if (mediumType.empty())
        {
            auto& log = spdmApp.getLog();
            if (log.logLevel >= LogClass::Level::Error)
            {
                log.iprint("Unable to get medium type for ");
                log.iprint(" EID = ");
                log.iprint(eidstrValue);
                log.iprint(" UUID = ");
                log.iprintln(uuid);
            }
            return;
        }

        auto bindingType = getBindingType(mctpObj.interfaces);
        if (bindingType.empty())
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

        auto transpSock = getTransportSocket(mctpObj.interfaces);
        if (transpSock.empty())
        {
            auto& log = spdmApp.getLog();
            if (log.logLevel >= LogClass::Level::Error)
            {
                log.iprint("Unable to get transport socket for ");
                log.iprint(" EID = ");
                log.iprint(eidstrValue);
                log.iprint(" UUID = ");
                log.iprint(uuid);
                log.iprint(" PATH = ");
                log.iprintln(mctpObj.path.str);
            }
            return;
        }
        tryConnectMCTP(transpSock);
#else
    const auto transpSock = "";
    auto mediumType = "";
    auto bindingType = "";
#endif
        dbus_api::ResponderArgs args{};
        if (eid.has_value())
        {
            auto eidvalue = eid.value();
            if (std::holds_alternative<unsigned char>(eidvalue))
            {
                args =
                    dbus_api::ResponderArgs{std::get<unsigned char>(eidvalue),
                                            uuid,
                                            mediumType,
                                            bindingType,
                                            mctpObj.path,
                                            objPath,
                                            std::move(transpSock)};
            }
            else if (std::holds_alternative<unsigned int>(eidvalue))
            {
                args = dbus_api::ResponderArgs{
                    static_cast<unsigned char>(
                        std::get<unsigned int>(eidvalue)),
                    uuid,
                    mediumType,
                    bindingType,
                    mctpObj.path,
                    objPath,
                    std::move(transpSock)};
            }
            spdmApp.discoveryUpdateResponder(args);
        }
    });
}
#endif

MctpDiscovery::EidType
    MctpDiscovery::getEid(const dbus::InterfaceMap& interfaces)
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
    return std::nullopt;
}

MctpDiscovery::EidType
    MctpDiscovery::getEid(const std::map<std::string, dbus::Value>& properties)
{

    SPDMCPP_LOG_TRACE_FUNC(spdmApp.getLog());

    if (!properties.contains(mctpEndpointIntfPropertyEid))
    {
        return std::nullopt;
    }
    if (!properties.contains(mctpEndpointIntfPropertySupportedMessageTypes))
    {
        return std::nullopt;
    }

    EidType eid = std::nullopt;
    /* Type of EID property depends on the system,
     *  so checking of all possible types is mandatory */
    try
    {
        if (auto uint32eid = std::get_if<unsigned int>(
                &properties.at(mctpEndpointIntfPropertyEid)))
        {
            eid = *uint32eid;
        }
        else if (auto uint8eid = std::get_if<unsigned char>(
                     &properties.at(mctpEndpointIntfPropertyEid)))
        {
            eid = *uint8eid;
        }
    }
    catch (const std::bad_variant_access& e)
    {
        spdmApp.getLog().println(e.what());
    }

    if (eid)
    {
        if (std::holds_alternative<uint8_t>(*eid) &&
            std::get<uint8_t>(*eid) < std::get<uint8_t>(invalidEid))
        {
            try
            {
                auto types = std::get<std::vector<uint8_t>>(properties.at(
                    mctpEndpointIntfPropertySupportedMessageTypes));
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
        else if (std::holds_alternative<uint32_t>(*eid) &&
                 std::get<uint32_t>(*eid) < std::get<uint32_t>(invalidEid))
        {
            try
            {
                auto types = std::get<std::vector<uint8_t>>(properties.at(
                    mctpEndpointIntfPropertySupportedMessageTypes));
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
    }

    return std::nullopt;
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

std::string MctpDiscovery::getMediumType(const dbus::InterfaceMap& interfaces)
{
    try
    {
        auto intf = interfaces.find(mctpEndpointIntfName);
        std::string mediumType;
        if (intf != interfaces.end())
        {
            const auto& properties = intf->second;
            if (!properties.contains(
                    std::string(mctpEndpointIntfPropertyMediumType)))
            {
                return "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.PCIe";
            }
            mediumType = std::get<std::string>(
                properties.at(std::string(mctpEndpointIntfPropertyMediumType)));
        }
        return mediumType;
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
    return {};
}

std::string MctpDiscovery::getBindingType(const dbus::InterfaceMap& interfaces)
{
    try
    {
        std::string bindingType;
        auto intf = interfaces.find(mctpBindingIntfProperty);
        if (intf != interfaces.end())
        {
            const auto& properties = intf->second;
            if (properties.contains(
                    std::string(mctpBindingIntfPropertyBindType)))
            {
                bindingType = std::get<std::string>(
                    properties.at(mctpBindingIntfPropertyBindType));
            }
        }
        return bindingType;
    }
    catch (const std::exception& e)
    {
        spdmApp.getLog().print(e.what());
    }
    {
        auto& log = spdmApp.getLog();
        if (log.logLevel >= LogClass::Level::Error)
        {
            log.println("Unable to determine binding type. Interfaces path:");
            for (const auto& [path, _] : interfaces)
            {
                log.println(path);
            }
        }
    }

    return {};
}

void MctpDiscovery::initCsmStatus()
{
#ifdef CSM_SERVICE_ENABLED
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
#else
    ccsmReady = true;
    setupMCTPServices();
#ifndef DISCOVERY_ONLY_FROM_MCTP_CONTROL
    while (!inventorySignalQueue.empty())
    {
        const auto& [path, ifc] = inventorySignalQueue.front();
        inventoryNewObjectSignal(path, ifc);
        inventorySignalQueue.pop_front();
    }
#endif
#endif
}

} // namespace spdmd
