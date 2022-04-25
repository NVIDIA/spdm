#include "mctp_endpoint_discovery.hpp"

#include "utils.hpp"

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
                                       "xyz.openbmc_project.MCTP.Control");
dbus::ServiceHelper inventoryService("/xyz/openbmc_project/inventory",
                                     "org.freedesktop.DBus.ObjectManager",
                                     "xyz.openbmc_project.Inventory.Manager");

MctpDiscovery::MctpDiscovery(SpdmdApp& spdmApp) :
    bus(spdmApp.getBus()), spdmApp(spdmApp),
    mctpEndpointSignal(
        spdmApp.getBus(),
        sdbusplus::bus::match::rules::interfacesAdded(
            mctpControlService.getPath()),
        std::bind_front(&MctpDiscovery::newEndpointDiscovered, this))
{
    dbus::ObjectValueTree objects;

    SPDMCPP_LOG_TRACE_FUNC(spdmApp.getLog());

    try
    {
        auto method =
            mctpControlService.new_method_call(bus, "GetManagedObjects");
        auto reply = bus.call(method);
        reply.read(objects);
    }
    catch (const std::exception& e)
    {
        spdmApp.getLog().iprintln(e.what());
        throw;
    }

    for ([[maybe_unused]] const auto& [objectPath, interfaces] : objects)
    {
        addNewEndpoint(objectPath, interfaces);
    }
}

void MctpDiscovery::newEndpointDiscovered(sdbusplus::message::message& msg)
{
    sdbusplus::message::object_path objPath;
    std::map<std::string, std::map<std::string, dbus::Value>> interfaces;
    msg.read(objPath, interfaces);

    addNewEndpoint(objPath, interfaces);
}

void MctpDiscovery::addNewEndpoint(const sdbusplus::message::object_path& objectPath, const std::map<std::string, std::map<std::string, dbus::Value>>& interfaces)
{
    for (const auto& intf : interfaces)
    {
        if (intf.first == mctpEndpointIntfName)
        {
            size_t eid = getEid(intf.second);
            if (eid < invalidEid)
            {
                auto uuid = getUUID(interfaces);
                if (!uuid.empty()) {
                    spdmApp.createResponder((mctp_eid_t)eid,
                                            getInventoryPath(uuid));
                }
                else {
                    spdmApp.reportError(std::string("SPDM MctpDiscovery couldn't get UUID for path '") + std::string(objectPath) + '\'');
                    spdmApp.createResponder((mctp_eid_t)eid, std::string());
                }
            }
        }
    }
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
            return std::get<std::string>(uuid->second);
        }
    }
    return std::string();
}

std::string MctpDiscovery::getInventoryPath(const std::string& uuid)
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
            if (interfaces.contains(
                    "xyz.openbmc_project.Inventory.Item.SPDMResponder"))
            {
                auto id = getUUID(interfaces);
                if (id == uuid)
                {
                    return std::string(objectPath);
                }
            }
        }
    }
    catch (const std::exception& e)
    {
        spdmApp.getLog().print(e.what());
    }
    spdmApp.reportError(std::string("SPDM MctpDiscovery couldn't get Inventory path for UUID '") + uuid + '\'');
    return std::string();
}

} // namespace spdmd
