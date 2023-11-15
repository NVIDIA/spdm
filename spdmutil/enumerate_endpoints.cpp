#include "enumerate_endpoints.hpp"

#include "enumerate_utils.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>

#include <iostream>

using namespace spdmcpp;

namespace spdmt
{

EnumerateEndpoints::EnumerateEndpoints(nlohmann::json& json,
                                       spdmcpp::TransportMedium medium,
                                       std::optional<int> busNum) :
    jsonObj(json)
{
#ifdef USE_DEFAULT_DBUS
    auto bus = sdbusplus::bus::new_default();
#else
    auto bus = sdbusplus::bus::new_system();
#endif
    exploreObjects(bus, medium, busNum);
}

auto EnumerateEndpoints::mediumDbusIfc(TransportMedium medium,
                                       std::optional<int> busNum) -> std::string
{
    switch (medium)
    {
        case TransportMedium::PCIe:
            return "xyz.openbmc_project.MCTP.Control.PCIe";
        case TransportMedium::SPI:
            return "xyz.openbmc_project.MCTP.Control.SPI";
        case TransportMedium::I2C:
            return "xyz.openbmc_project.MCTP.Control.SMBus" +
                   std::to_string(*busNum);
    }
    return "";
}
auto EnumerateEndpoints::exploreObjects(sdbusplus::bus::bus& bus,
                                        spdmcpp::TransportMedium medium,
                                        std::optional<int> busNum) -> void
{
    constexpr auto interfacePath = "/xyz/openbmc_project/mctp";
    const auto interfaceName = mediumDbusIfc(medium, busNum);
    auto method = bus.new_method_call(interfaceName.c_str(), interfacePath,
                                      "org.freedesktop.DBus.ObjectManager",
                                      "GetManagedObjects");
    auto reply = bus.call(method);
    DbusObjectValueTree objects;
    reply.read(objects);
    for (const auto& [path, ifc] : objects)
    {
        exploreMctpItem(path, ifc);
    }
}

auto EnumerateEndpoints::exploreMctpItem(
    const sdbusplus::message::object_path& path, const DbusInterfaceMap& ifc)
    -> void
{
    auto eid = getEid(ifc);
    auto uuid = getUUID(ifc);
    if (eid.has_value())
    {
        jsonObj["Endpoints"].push_back(
            {{"Path", path.str}, {"EID", *eid}, {"UUID", uuid}});
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

} // namespace spdmt