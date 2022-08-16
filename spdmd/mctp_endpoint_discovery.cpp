#include "mctp_endpoint_discovery.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <string_view>
#include <vector>

// #define MCTP_EID_PATH

namespace spdmd
{

constexpr size_t invalidEid = 256;

dbus::ServiceHelper mctpControlService("/xyz/openbmc_project/mctp",
                                       "org.freedesktop.DBus.ObjectManager",
                                       "xyz.openbmc_project.MCTP.Control.PCIe");

MctpDiscovery::MctpDiscovery(SpdmdApp& spdmApp) :
    bus(spdmApp.getBus()), spdmApp(spdmApp),
    mctpEndpointSignal(
        spdmApp.getBus(),
        sdbusplus::bus::match::rules::interfacesAdded(
#ifdef MCTP_EID_PATH
            mctpControlService.getPath()
#else
            inventoryService.getPath()
#endif
                ),
        std::bind_front(&MctpDiscovery::newEndpointDiscovered, this))
{
    dbus::ObjectValueTree objects;

    SPDMCPP_LOG_TRACE_FUNC(spdmApp.getLog());

    try
    {
#ifdef MCTP_EID_PATH
        auto& service = mctpControlService;
#else
        auto& service = inventoryService;
#endif
        auto method = service.new_method_call(bus, "GetManagedObjects");
        auto reply = bus.call(method);
        reply.read(objects);
    }
    catch (const std::exception& e)
    {
        spdmApp.getLog().iprintln(e.what());
        return;
    }

    for ([[maybe_unused]] const auto& [objectPath, interfaces] : objects)
    {
        addNewEndpoint(objectPath, interfaces);
    }
}

void MctpDiscovery::newEndpointDiscovered(sdbusplus::message::message& msg)
{
    sdbusplus::message::object_path objPath;
    dbus::InterfaceMap interfaces;
    msg.read(objPath, interfaces);

    addNewEndpoint(objPath, interfaces);
}

#ifdef MCTP_EID_PATH
void MctpDiscovery::addNewEndpoint(
    const sdbusplus::message::object_path& objectPath,
    const dbus::InterfaceMap& interfaces)
{
    // There is some issue with MCTP-PCIE CTRL daemon which starts,so
    // SPDM service gets started and after a moment MCTP daemon fails which is
    // causing the SPDM daemon to fail when it tries to connect the MCTP daemon
    // through the unix socket.
    if (spdmApp.responders.size() == 0)
    {
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

    size_t eid = getEid(interfaces);
    if (eid < invalidEid)
    {
        auto uuid = getUUID(interfaces);
        if (!uuid.empty())
        {
            spdmApp.createResponder((mctp_eid_t)eid, objectPath,
                                    getInventoryPath(uuid));
        }
        else
        {
            spdmApp.reportError(
                std::string("SPDM MctpDiscovery couldn't get UUID for path '") +
                std::string(objectPath) + '\'');
            spdmApp.createResponder((mctp_eid_t)eid, objectPath, {});
        }
    }
}
#else
void MctpDiscovery::addNewEndpoint(
    const sdbusplus::message::object_path& objectPath,
    const dbus::InterfaceMap& interfaces)
{
    if (!interfaces.contains(inventorySPDMResponderIntfName))
    {
        return;
    }
    if (spdmApp.responders.size() == 0)
    {
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

    auto uuid = getUUID(interfaces);
    if (uuid.empty())
    {
        spdmApp.reportError(
            std::string("SPDM MctpDiscovery couldn't get UUID for path '") +
            std::string(objectPath) + '\'');
        return;
    }

    auto mctp = getMCTP(uuid);
    size_t eid = getEid(mctp.interfaces);
    if (eid < invalidEid)
    {
        spdmApp.createResponder((mctp_eid_t)eid, mctp.path, objectPath);
    }
    else
    {
        spdmApp.reportError(
            std::string("SPDM MctpDiscovery couldn't get EID for UUID '") +
            uuid + '\'');
    }
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
    spdmApp.reportError(
        std::string("SPDM MctpDiscovery couldn't get MCTP path for UUID '") +
        uuid + '\'');
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
    spdmApp.reportError(
        std::string(
            "SPDM MctpDiscovery couldn't get Inventory path for UUID '") +
        uuid + '\'');
    return {};
}

} // namespace spdmd
