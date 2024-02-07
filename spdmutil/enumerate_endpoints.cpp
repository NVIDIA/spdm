#include "enumerate_endpoints.hpp"

#include "enumerate_utils.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>

#include <iostream>

using namespace spdmcpp;

namespace spdmt
{

EnumerateEndpoints::EnumerateEndpoints(std::string_view dbusIfc)
{
#ifdef USE_DEFAULT_DBUS
    auto bus = sdbusplus::bus::new_default();
#else
    auto bus = sdbusplus::bus::new_system();
#endif
    enumerateMCTPDBusObjects(bus, dbusIfc);
}


auto EnumerateEndpoints::enumerateMCTPDBusObjects(sdbusplus::bus::bus& bus,
        std::string_view dbusIfc) -> void
{
    constexpr auto interfacePath = "/xyz/openbmc_project/mctp";
    auto method = bus.new_method_call(std::string(dbusIfc).c_str(), interfacePath,
                                      "org.freedesktop.DBus.ObjectManager",
                                      "GetManagedObjects");
    auto reply = bus.call(method);
    DbusObjectValueTree objects;
    reply.read(objects);
    {
        for (const auto& [path, ifc] : objects)
        {
            exploreMctpItem(path, ifc);
        }
    }
}

auto EnumerateEndpoints::exploreMctpItem(
    const sdbusplus::message::object_path& path, const DbusInterfaceMap& ifc)
    -> void
{
    if (const auto eid = getEid(ifc); eid)
    {
        ResponderInfo info { *getEid(ifc), path, getUUID(ifc), getUnixSocketAddress(ifc) };
        respInfos.emplace_back( info );
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
            auto types = std::get<std::vector<uint8_t>>(
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

auto EnumerateEndpoints::getUUID(const DbusInterfaceMap& interfaces) -> std::string
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


auto EnumerateEndpoints::getUnixSocketAddress(const DbusInterfaceMap& interfaces) -> std::string
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
                    const auto vec = std::get<std::vector<uint8_t>>(addr->second);
                    return {vec.begin(), vec.end()};
                }
                catch(const std::exception& e)
                {
                }
            }
        }
    }
    catch(const std::exception& e)
    {
    }
    return {};

}
 

} // namespace spdmt