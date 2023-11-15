#pragma once

#include "enumerate_utils.hpp"

#include <nlohmann/json.hpp>
#include <sdbusplus/bus.hpp>
#include <spdmcpp/common.hpp>

#include <optional>
#include <string>

namespace spdmt
{

class EnumerateEndpoints
{
  public:
    /**
     * Enumerate MCTP SPDM endpoints
     * @param json Json object
     * @param medium Medium type
     * @param busNum Bus number
     */
    explicit EnumerateEndpoints(nlohmann::json& json,
                                spdmcpp::TransportMedium medium,
                                std::optional<int> busNum = std::nullopt);

  private:
    /** @brief Explore MCTP spdm objects */
    auto exploreObjects(sdbusplus::bus::bus& bus,
                        spdmcpp::TransportMedium medium,
                        std::optional<int> busNum) -> void;
    /** @brief Convert medium type to string*/
    static auto mediumDbusIfc(spdmcpp::TransportMedium medium,
                              std::optional<int> busNum) -> std::string;
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

  private:
    nlohmann::json& jsonObj;
};
} // namespace spdmt