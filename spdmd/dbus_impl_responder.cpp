#include "dbus_impl_responder.hpp"

#include "xyz/openbmc_project/Common/error.hpp"

#include <iostream>

using namespace sdbusplus::xyz::openbmc_project::Common::Error;

namespace spdm
{
namespace dbus_api
{

uint8_t Responder::getInstanceId(uint8_t eid)
{
    if (ids.find(eid) == ids.end())
    {
        InstanceId id;
        ids.emplace(eid, InstanceId());
    }

    uint8_t id{};
    try
    {
        id = ids[eid].next();
    }
    catch (const std::runtime_error& e)
    {
        throw TooManyResources();
    }

    return id;
}

} // namespace dbus_api
} // namespace spdm
