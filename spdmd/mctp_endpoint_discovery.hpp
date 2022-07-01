#pragma once

#include "spdmd_app.hpp"

#include <sdbusplus/bus/match.hpp>

namespace spdmd
{

using mctp_eid_t = uint8_t;
using createResponder_t = bool (*)(mctp_eid_t);
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
    struct Object
    {
        sdbusplus::message::object_path path;
        dbus::InterfaceMap interfaces;
        bool isValid() const
        {
            return !path.filename().empty();
        }
    };

    /** @brief reference to the systemd bus */
    sdbusplus::bus::bus& bus;

    /** @brief reference to the SPDM app, used to create responder */
    SpdmdApp& spdmApp;

    /** @brief Used to watch for new MCTP endpoints */
    sdbusplus::bus::match_t mctpEndpointSignal;

    /** @brief Called when a new mctp endpoint is discovered */
    void newEndpointDiscovered(sdbusplus::message::message& msg);

    /** @brief Common function for creating a responder object, either on start
     * or later when a new endpoint is discovered */
    void addNewEndpoint(const sdbusplus::message::object_path& objectPath,
                        const dbus::InterfaceMap& interfaces);

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

    static constexpr auto inventorySPDMResponderIntfName =
        "xyz.openbmc_project.Inventory.Item.SPDMResponder";

    static constexpr auto uuidIntfName = "xyz.openbmc_project.Common.UUID";

    static constexpr auto uuidIntfPropertyUUID = "UUID";
    //     static constexpr auto mctpEndpointIntfPropertyUUID =
    //         "SupportedMessageTypes";

    /** @brief Get EID value from MCTP objects, which implement SPDM
     *  @returns EID or invalidEid (256) in case of error
     */
    size_t getEid(const dbus::InterfaceMap& interfaces);

    /** @brief Get EID value from MCTP objects, which implement SPDM
     *  @returns EID or invalidEid (256) in case of error
     */
    size_t getEid(const std::map<std::string, dbus::Value>& properties);

    /** @brief Extract UUID value from the object's interfaces */
    std::string getUUID(const dbus::InterfaceMap& interfaces);

    /** @brief get an object from MCTP.Control with the provided uuid
     */
    Object getMCTP(const std::string& uuid);

    /** @brief get a path from the inventory to an object with the provided uuid
     */
    sdbusplus::message::object_path getInventoryPath(const std::string& uuid);
};

} // namespace spdmd
