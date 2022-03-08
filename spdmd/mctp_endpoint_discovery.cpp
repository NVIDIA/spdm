#include "mctp_endpoint_discovery.hpp"

#include "utils.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace spdmd
{

MctpDiscovery::MctpDiscovery(SpdmdApp& spdmApp) :
    bus(spdmApp.getBus()), spdmApp(spdmApp),
    mctpEndpointSignal(spdmApp.getBus(),
                       sdbusplus::bus::match::rules::interfacesAdded(
                           "/xyz/openbmc_project/mctp"),
                       std::bind_front(&MctpDiscovery::dicoverEndpoints, this))
{
    dbus::ObjectValueTree objects;

    SPDMCPP_LOG_TRACE_FUNC(spdmApp.log);

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
        spdmApp.log.print(e.what());
        return;
    }

    for (const auto& [objectPath, interfaces] : objects)
    {
        for (const auto& [intfName, properties] : interfaces)
        {
            if (intfName == mctpEndpointIntfName)
            {
                size_t eid = (mctp_eid_t)getEid(properties);
                if (eid < 256)
                {
                    spdmApp.createResponder((mctp_eid_t)eid);
                }
            }
        }
    }
}

void MctpDiscovery::dicoverEndpoints(sdbusplus::message::message& msg)
{
    sdbusplus::message::object_path objPath;
    std::map<std::string, std::map<std::string, dbus::Value>> interfaces;
    msg.read(objPath, interfaces);

    for (const auto& [intfName, properties] : interfaces)
    {
        if (intfName == mctpEndpointIntfName)
        {
            size_t eid = (mctp_eid_t)getEid(properties);
            if (eid < 256)
            {
                spdmApp.createResponder((mctp_eid_t)eid);
            }
        }
    }
}

size_t MctpDiscovery::getEid(std::map<std::string, dbus::Value> properties)
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
            catch (const std::bad_variant_access& e)
            {
                spdmApp.log.println(e.what());
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
                spdmApp.log.print(e.what());
            }
        }
    }

    return 256;
}

} // namespace spdmd