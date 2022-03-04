#pragma once

#include "spdmd_app_context.hpp"

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

namespace dbus_api
{

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

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     */
    Responder(SpdmdAppContext& appCtx, const std::string& path, uint8_t eid);

    ~Responder();

    void refresh(uint8_t slot, std::vector<uint8_t> nonce,
                 uint32_t sessionId) override;

    spdmcpp::LogClass& getLog()
    {
        return Connection.getLog();
    }

    spdmcpp::RetStat handleRecv(std::vector<uint8_t>& buf);

  protected:
    typedef std::vector<std::tuple<
        uint8_t,
        std::vector<std::tuple<uint8_t, uint8_t, std::vector<uint8_t>>>>>
        MeasurementsContainerType;
    typedef std::vector<std::tuple<uint8_t, std::vector<uint8_t>>>
        CertificatesContainerType;

    SpdmdAppContext& appContext;

    spdmcpp::ConnectionClass Connection;
    MCTP_TransportClass Transport;

    void updateLastUpdateTime();
    void syncSlotsInfo();

    friend MCTP_TransportClass;
};

} // namespace dbus_api
} // namespace spdmd
