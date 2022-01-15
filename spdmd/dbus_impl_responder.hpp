#pragma once

#include "instance_id.hpp"

#include "xyz/openbmc_project/SPDM/Responder/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>

#include <map>

namespace spdm
{
namespace dbus_api
{

using ResponderIntf = sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::SPDM::server::Responder>;

/** @class Responder
 *  @brief OpenBMC SPDM.Responder implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.SPDM.Responder DBus APIs.
 */
class Responder : public ResponderIntf
{
  public:
    Responder() = delete;
    Responder(const Responder&) = delete;
    Responder& operator=(const Responder&) = delete;
    Responder(Responder&&) = delete;
    Responder& operator=(Responder&&) = delete;
    virtual ~Responder() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     */
    Responder(sdbusplus::bus::bus& bus, const std::string& path) :
        ResponderIntf(bus, path.c_str()){};

    /** @brief Implementation for RequesterIntf.GetInstanceId */
    uint8_t getInstanceId(uint8_t eid);

    /** @brief Mark an instance id as unused
     *  @param[in] eid - MCTP eid to which this instance id belongs
     *  @param[in] instanceId - SPDM instance id to be freed
     *  @note will throw std::out_of_range if instanceId > 31
     */
    void markFree(uint8_t eid, uint8_t instanceId)
    {
        ids[eid].markFree(instanceId);
    }

  private:
    /** @brief EID to SPDM Instance ID map */
    std::map<uint8_t, InstanceId> ids;
};

} // namespace dbus_api
} // namespace spdm
