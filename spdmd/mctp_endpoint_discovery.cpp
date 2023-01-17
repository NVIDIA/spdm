#include "mctp_endpoint_discovery.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace spdmd
{

constexpr size_t invalidEid = 256;

dbus::ServiceHelper mctpControlService("/xyz/openbmc_project/mctp",
                                       "org.freedesktop.DBus.ObjectManager",
                                       "xyz.openbmc_project.MCTP.Control.PCIe");

MctpDiscovery::MctpDiscovery(SpdmdApp& spdmApp) :
    bus(spdmApp.getBus()), spdmApp(spdmApp),
#ifndef DISCOVERY_ONLY_FROM_MCTP_CONTROL
    inventoryMatch(spdmApp.getBus(),
        sdbusplus::bus::match::rules::interfacesAdded(
            inventoryService.getPath()),
            [this](sdbusplus::message::message& msg) {
                sdbusplus::message::object_path objPath;
                dbus::InterfaceMap interfaces;
                msg.read(objPath, interfaces);
                inventoryNewObjectSignal(objPath, interfaces);
            }),
#endif
    mctpMatch(spdmApp.getBus(),
        sdbusplus::bus::match::rules::interfacesAdded(
            mctpControlService.getPath()
        ),
        [this](sdbusplus::message::message& msg) {
            sdbusplus::message::object_path objPath;
            dbus::InterfaceMap interfaces;
            msg.read(objPath, interfaces);
            mctpNewObjectSignal(objPath, interfaces);
        })
{
    dbus::ObjectValueTree objects;

    SPDMCPP_LOG_TRACE_FUNC(spdmApp.getLog());

    try
    {
        auto& service = mctpControlService;
        auto method = service.new_method_call(bus, "GetManagedObjects");
        auto reply = bus.call(method);
        reply.read(objects);
    }
    catch (const std::exception& e)
    {
        spdmApp.getLog().iprintln(e.what());
        return;
    }

    for (const auto& [objectPath, interfaces] : objects)
    {
        mctpNewObjectSignal(objectPath, interfaces);
    }
}


void MctpDiscovery::tryConnectMCTP()
{
    // There is some issue with MCTP-PCIE CTRL daemon which starts,so
    // SPDM service gets started and after a moment MCTP daemon fails which is
    // causing the SPDM daemon to fail when it tries to connect the MCTP daemon
    // through the unix socket.
    try
    {
        spdmApp.connectMCTP();
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
    tryConnectMCTP();

    size_t eid = getEid(interfaces);
    if (eid == invalidEid)
    {
        spdmApp.getLog().iprintln("SPDM mctpNewObjectSignal couldn't get EID for path '"s + std::string(objPath) + '\'');
        return;
    }

    auto uuid = getUUID(interfaces);

#ifdef DISCOVERY_ONLY_FROM_MCTP_CONTROL
    std::string invPath;
#else
    if (uuid.empty()) {
        spdmApp.getLog().iprintln("SPDM mctpNewObjectSignal couldn't get UUID for path '"s + std::string(objPath) + '\'');
        return;
    }
    auto invPath = getInventoryPath(uuid);
    if (invPath.filename().empty()) {
        spdmApp.getLog().iprintln("SPDM mctpNewObjectSignal couldn't get inventory path for UUID'"s + uuid + '\'');
        return;
    }
#endif

    auto mediumType = getMediumType(interfaces);
    dbus_api::ResponderArgs args { mctp_eid_t(eid), uuid, mediumType, objPath, invPath };
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

    tryConnectMCTP();

    auto uuid = getUUID(interfaces);
    if (uuid.empty())
    {
        spdmApp.getLog().iprintln("SPDM inventoryNewObjectSignal couldn't get UUID for path '"s + std::string(objPath) + '\'');
        return;
    }

    auto mctp = getMCTP(uuid);
    size_t eid = getEid(mctp.interfaces);
    if (eid == invalidEid)
    {
        spdmApp.getLog().iprintln("SPDM inventoryNewObjectSignal couldn't get EID for UUID '"s + uuid + '\'');
        return;
    }
    auto mediumType = getMediumType(interfaces);
    dbus_api::ResponderArgs args { mctp_eid_t(eid), uuid, mediumType, mctp.path, objPath };
    spdmApp.discoveryUpdateResponder(args);
}
#endif

size_t MctpDiscovery::getEid(const dbus::InterfaceMap& interfaces)
{
    auto intf = interfaces.find(mctpEndpointIntfName);
    if (intf != interfaces.end())
    {
        return getEid(intf->second);
    }
    return invalidEid;
}

size_t
    MctpDiscovery::getEid(const std::map<std::string, dbus::Value>& properties)
{
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

std::string MctpDiscovery::getUUID(const dbus::InterfaceMap& interfaces)
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
    return {};
}

MctpDiscovery::Object MctpDiscovery::getMCTP(const std::string& uuid)
{
    dbus::ObjectValueTree objects;

    SPDMCPP_LOG_TRACE_FUNC(spdmApp.getLog());

    try
    {
        auto method =
            mctpControlService.new_method_call(bus, "GetManagedObjects");
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
    auto intf = interfaces.find(mctpEndpointIntfName);
    if (intf != interfaces.end())
    {
        return getMediumType(intf->second);
    }
    return std::nullopt;
}

std::optional<spdmcpp::TransportMedium> MctpDiscovery::getMediumType(const std::map<std::string, dbus::Value>& properties)
{
    if (!properties.contains(mctpEndpointIntfPropertyMediumType))
    {
        return spdmcpp::TransportMedium::PCIe;
    }
    std::string mediumTypeStr;

    try
    {
        mediumTypeStr = std::get<std::string>(properties.at(mctpEndpointIntfPropertyMediumType));
        mediumTypeStr = mediumTypeStr.substr(mediumTypeStr.find_last_of('.')+1);
    }
    catch (const std::bad_variant_access& e)
    {
        return std::nullopt;
    }
    catch (const std::exception& e)
    {
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
    return std::nullopt;
}



} // namespace spdmd
