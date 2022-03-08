#pragma once

#include "spdmd_app.hpp"

#include <sdbusplus/bus/match.hpp>

namespace spdmd
{

typedef uint8_t mctp_eid_t;
typedef bool (*createResponder_t)(mctp_eid_t eid);
class SpdmdApp;

class MctpDiscovery
{
  public:
    MctpDiscovery() = delete;
    MctpDiscovery(const MctpDiscovery&) = delete;
    MctpDiscovery(MctpDiscovery&&) = delete;
    MctpDiscovery& operator=(const MctpDiscovery&) = delete;
    MctpDiscovery& operator=(MctpDiscovery&&) = delete;
    ~MctpDiscovery() = default;

    /** @brief Constructs the MCTP Discovery object to handle discovery of
     *         MCTP and SPDM enabled devices
     *
     *  @param[in] bus - reference to systemd bus
     *  @param[in] createResponder - reference to create Responder function
     */
    explicit MctpDiscovery(SpdmdApp& spdmApp);

  private:
    /** @brief reference to the systemd bus */
    sdbusplus::bus::bus& bus;

    /** @brief reference to the SPDM app, used to create responder */
    SpdmdApp& spdmApp;

    /** @brief Used to watch for new MCTP endpoints */
    sdbusplus::bus::match_t mctpEndpointSignal;

    void dicoverEndpoints(sdbusplus::message::message& msg);

    /** @brief SPDM type of an MCTP message */
    static constexpr uint8_t mctpTypeSPDM = 5;

    /** @brief MCTP d-bus interface name  */
    static constexpr auto mctpEndpointIntfName =
        "xyz.openbmc_project.MCTP.Endpoint";

    /** @brief MCTP d-bus interface, property name EID  */
    static constexpr auto mctpEndpointIntfPropertyEid = "EID";

    /** @brief MCTP d-bus interface, property name EID  */
    static constexpr auto mctpEndpointIntfPropertySupportedMessageTypes =
        "SupportedMessageTypes";

    /** @brief Get EID value from MCTP objects, which implement SPDM  */
    size_t getEid(std::map<std::string, dbus::Value> properties);
};

} // namespace spdmd