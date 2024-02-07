#pragma once

#include "enumerate_utils.hpp"
#include <sdbusplus/bus.hpp>
#include <spdmcpp/common.hpp>

#include <optional>
#include <string>

namespace spdmt
{


/** @brief Responder info structure used for discovery */
struct ResponderInfo
{
    size_t eid;           //! Endpoint identifier
    std::string path;     //! Responder path
    std::string uuid;     //! UUID responder
    std::string sockPath; //! Unix socket path
};

class EnumerateEndpoints
{
  public:
    /**
     * Enumerate MCTP SPDM endpoints
     * @param dbusIfc Dbus inteface
     */
    explicit EnumerateEndpoints( std::string_view dbusIfc);

    /**
     * @brief Get enumerated responders information
    */
    auto& getRespondersInfo() const noexcept
    {
      return respInfos;
    }

  private:
    /** @brief Explore MCTP spdm objects */
    auto enumerateMCTPDBusObjects(sdbusplus::bus::bus& bus,
                        std::string_view dbusIfc) -> void;
    /** @brief Explore single item */
    auto exploreMctpItem(const sdbusplus::message::object_path& path,
                         const DbusInterfaceMap& ifc) -> void;
    /** @brief Get endpoint EID*/
    auto getEid(const DbusInterfaceMap& ifc) -> std::optional<size_t>;
    /** @brief Get endpoint EID*/
    auto getEid(const std::map<std::string, DbusValue>& prop)
        -> std::optional<size_t>;
    /** @brief Get endpoint UUID*/
    auto getUUID(const DbusInterfaceMap& ifc) -> std::string;
    /** @brief Get transport socket */
    auto getUnixSocketAddress(const DbusInterfaceMap& ifc) -> std::string;

  private:
    std::vector<ResponderInfo> respInfos;
};
} // namespace spdmt