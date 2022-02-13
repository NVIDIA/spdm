#pragma once

#include "instance_id.hpp"
#include "xyz/openbmc_project/SPDM/Responder/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdeventplus/event.hpp>
#include <sdeventplus/source/io.hpp>
#include <sdeventplus/source/time.hpp>
#include <spdmcpp/connection.hpp>
#include <spdmcpp/mctp_support.hpp>

#include <map>

namespace spdmd
{

struct ResponderContext
{
    spdmcpp::ContextClass context;
    sdeventplus::Event event;
    sdbusplus::bus::bus bus;

    ResponderContext(sdeventplus::Event&& e, sdbusplus::bus::bus&& b) :
        event(std::move(e)), bus(std::move(b))
    {}
};

namespace dbus_api
{

using ResponderIntf = sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::SPDM::server::Responder>;

class Responder;

class MCTP_TransportClass : public spdmcpp::MCTP_TransportClass
{
  public:
    MCTP_TransportClass(uint8_t eid, Responder& resp) :
        spdmcpp::MCTP_TransportClass(eid), responder(resp)
    {}
    virtual ~MCTP_TransportClass()
    {
        if (time)
        {
            delete time;
            time = nullptr;
        }
    }

    virtual spdmcpp::RetStat
        setup_timeout(spdmcpp::timeout_ms_t timeout) override;

    virtual bool clear_timeout() override;

  protected:
    static constexpr sdeventplus::ClockId clockId =
        sdeventplus::ClockId::Monotonic;
    Responder& responder;
    sdeventplus::source::Time<clockId>* time = nullptr;
};

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

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     */
    Responder(ResponderContext& ctx, const std::string& path, uint8_t eid);

    ~Responder();

#if 0
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
#endif
    /** @brief Implementation for Refresh
     *  Use this method to get all fresh measurements and certificates.
     *  The method is asynchronous, so it returns immediately.
     *  Current status of communication between the SPDM requester and
     *  responder may be verified using the Status property.
     */
    void refresh() override;

    spdmcpp::LogClass& getLog()
    {
        return Connection.getLog();
    }

    spdmcpp::RetStat handleRecv(std::vector<uint8_t>& buf);

  protected:
    typedef std::vector<
        std::tuple<std::vector<uint8_t>, MeasurementsType, HashingAlgorithms>>
        MeasurementsContainerType;

    ResponderContext& context;

    spdmcpp::ConnectionClass Connection;
    MCTP_TransportClass Transport;

    void updateLastUpdateTime();

    friend MCTP_TransportClass;
};

} // namespace dbus_api
} // namespace spdmd
