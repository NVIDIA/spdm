#include "mctp_endpoint_discovery.hpp"

#include "utils.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace spdmd
{

const std::string inventoryDefaultPath = "/xyz/openbmc_project/inventory";

MctpDiscovery::MctpDiscovery(SpdmdApp& spdmApp) :
    bus(spdmApp.getBus()), spdmApp(spdmApp),
    mctpEndpointSignal(
        spdmApp.getBus(),
        sdbusplus::bus::match::rules::interfacesAdded(
            "/xyz/openbmc_project/mctp"),
        std::bind_front(&MctpDiscovery::newEndpointDiscovered, this))
{
    dbus::ObjectValueTree objects;

    SPDMCPP_LOG_TRACE_FUNC(spdmApp.getLog());

    try
    {
        auto method = bus.new_method_call(
            "xyz.openbmc_project.MCTP.Control", "/xyz/openbmc_project/mctp",
            "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
        auto reply = bus.call(method);
        reply.read(objects);
    }
    catch (const std::exception& e)
    {
        spdmApp.getLog().print(e.what());
        return;
    }

    for ([[maybe_unused]] const auto& [objectPath, interfaces] : objects)
    {
        for (const auto& intf : interfaces)
        {
            if (intf.first == mctpEndpointIntfName)
            {
                size_t eid = getEid(intf.second);
                if (eid < 256)
                {
                    spdmApp.createResponder(
                        (mctp_eid_t)eid, getInventoryPath(getUUID(interfaces)));
                }
            }
        }
    }
}

void MctpDiscovery::newEndpointDiscovered(sdbusplus::message::message& msg)
{
    sdbusplus::message::object_path objPath;
    std::map<std::string, std::map<std::string, dbus::Value>> interfaces;
    msg.read(objPath, interfaces);

    for (const auto& intf : interfaces)
    {
        if (intf.first == mctpEndpointIntfName)
        {
            size_t eid = getEid(intf.second);
            if (eid < 256)
            {
                spdmApp.createResponder((mctp_eid_t)eid,
                                        getInventoryPath(getUUID(interfaces)));
            }
        }
    }
}

size_t
    MctpDiscovery::getEid(const std::map<std::string, dbus::Value>& properties)
{
    if (properties.contains(mctpEndpointIntfPropertyEid) &&
        properties.contains(mctpEndpointIntfPropertySupportedMessageTypes))
    {
        size_t eid = 256;
        /* Type of EID property depends on the system,
         *  so checking of all possible types is mandatory */
        try
        {
            eid =
                std::get<uint32_t>(properties.at(mctpEndpointIntfPropertyEid));
        }
        catch (const std::bad_variant_access& e)
        {
            try
            {
                eid = std::get<size_t>(
                    properties.at(mctpEndpointIntfPropertyEid));
            }
            catch (const std::bad_variant_access& e1)
            {
                spdmApp.getLog().println(e1.what());
            }
        }
        if (eid < 256)
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

    return 256;
}

std::string MctpDiscovery::getUUID(const dbus::InterfaceMap& interfaces)
{
    auto intf = interfaces.find(uuidIntfName);
    if (intf != interfaces.end())
    {
        const auto& properties = intf->second;
        {
            auto uuid = properties.find(uuidIntfPropertyUUID);
            if (uuid != properties.end())
            {
                return std::get<std::string>(uuid->second);
            }
        }
    }
    return "";
}

std::string MctpDiscovery::getInventoryPath(const std::string& uuid)
{
    dbus::ObjectValueTree objects;

    SPDMCPP_LOG_TRACE_FUNC(spdmApp.getLog());

    // TODO couldn't test/verify so this is most likely invalid/broken
    try
    {
        auto method = bus.new_method_call(
            "xyz.openbmc_project.Inventory.Manager",
            inventoryDefaultPath.c_str(), "org.freedesktop.DBus.ObjectManager",
            "GetManagedObjects");
        auto reply = bus.call(method);
        reply.read(objects);

        for (const auto& [objectPath, interfaces] : objects)
        {
            if (interfaces.contains(
                    "xyz.openbmc_project.Inventory.Item.SPDMResponder"))
            {
                std::string id = getUUID(interfaces);
                if (id == uuid)
                {
                    return inventoryDefaultPath + "/" + std::string(objectPath);
                }
            }
        }
    }
    catch (const std::exception& e)
    {
        spdmApp.getLog().print(e.what());
    }
    return inventoryDefaultPath + "/INVALID";
}

} // namespace spdmd
