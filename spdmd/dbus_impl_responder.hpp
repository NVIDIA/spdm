#pragma once

#include "spdmd_app_context.hpp"
#include "xyz/openbmc_project/Association/Definitions/server.hpp"
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

/** @class MctpTransportClass
 *  @brief Support class for transport through the mctp-demux-daemon with
 * timeouts handled by sdeventplus
 */
class MctpTransportClass : public spdmcpp::MctpTransportClass
{
  public:
    MctpTransportClass(uint8_t eid, Responder& resp) :
        spdmcpp::MctpTransportClass(eid), responder(resp)
    {}
    virtual ~MctpTransportClass()
    {
        if (time)
        {
            delete time;
            time = nullptr;
        }
    }

    virtual spdmcpp::RetStat
        setupTimeout(spdmcpp::timeout_ms_t timeout) override;

    virtual bool clearTimeout() override;

  protected:
    static constexpr sdeventplus::ClockId clockId =
        sdeventplus::ClockId::Monotonic;
    Responder& responder;
    sdeventplus::source::Time<clockId>* time = nullptr;
};

using ResponderIntf = sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::SPDM::server::Responder,
    sdbusplus::xyz::openbmc_project::Association::server::Definitions>;

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
    Responder(SpdmdAppContext& appCtx, const std::string& path, uint8_t eid,
              const std::string& inventoryPath);

    ~Responder();

    void refresh(uint8_t slot, std::vector<uint8_t> nonc,
                 std::vector<uint8_t> measurementIndices,
                 uint32_t sessionId) override;

    spdmcpp::LogClass& getLog()
    {
        return Connection.getLog();
    }

    spdmcpp::RetStat handleRecv(std::vector<uint8_t>& buf);

  protected:
    using MeasurementsContainerType = std::vector<std::tuple<uint8_t, uint8_t, std::vector<uint8_t>>>;
    using CertificatesContainerType = std::vector<std::tuple<uint8_t, std::vector<uint8_t>>>;

    SpdmdAppContext& appContext;

    spdmcpp::ConnectionClass Connection;
    MctpTransportClass Transport;

    void updateLastUpdateTime();
    void syncSlotsInfo();

    friend MctpTransportClass;
};

} // namespace dbus_api
} // namespace spdmd
