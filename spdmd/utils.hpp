#pragma once

//#include "types.hpp"

#include <systemd/sd-bus.h>
#include <unistd.h>

#include <sdbusplus/server.hpp>
#include <xyz/openbmc_project/Logging/Entry/server.hpp>

#include <cstdint>
#include <exception>
#include <filesystem>
#include <iostream>
#include <string>
#include <variant>
#include <vector>

using namespace std;

namespace spdmd
{

namespace dbus
{
using ObjectPath = std::string;
using Service = std::string;
using Interface = std::string;
using Interfaces = std::vector<std::string>;
using Property = std::string;
using PropertyType = std::string;
using Value =
    std::variant<bool, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t,
                 uint64_t, double, std::string, std::vector<uint8_t>>;

using PropertyMap = std::map<Property, Value>;
using InterfaceMap = std::map<Interface, PropertyMap>;
using ObjectValueTree = std::map<sdbusplus::message::object_path, InterfaceMap>;

} // namespace dbus

namespace utils
{

namespace fs = std::filesystem;

/**
 *  @brief creates an error log
 *  @param[in] errorMsg - the error message
 */
void reportError(const char* errorMsg);

constexpr auto dbusProperties = "org.freedesktop.DBus.Properties";
constexpr auto mapperService = "xyz.openbmc_project.ObjectMapper";

struct DBusMapping
{
    std::string objectPath;   //!< D-Bus object path
    std::string interface;    //!< D-Bus interface
    std::string propertyName; //!< D-Bus property name
    std::string propertyType; //!< D-Bus property type
};

using PropertyValue =
    std::variant<bool, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t,
                 uint64_t, double, std::string>;
using DbusProp = std::string;
using DbusChangedProps = std::map<DbusProp, PropertyValue>;
using DBusInterfaceAdded = std::vector<
    std::pair<spdmd::dbus::Interface,
              std::vector<std::pair<spdmd::dbus::Property,
                                    std::variant<spdmd::dbus::Property>>>>>;
using ObjectPath = std::string;
using ServiceName = std::string;
using Interfaces = std::vector<std::string>;
using MapperServiceMap = std::vector<std::pair<ServiceName, Interfaces>>;
using GetSubTreeResponse = std::vector<std::pair<ObjectPath, MapperServiceMap>>;

/**
 * @brief The interface for DBusHandler
 */
//NOLINTNEXTLINE cppcoreguidelines-special-member-functions
class DBusHandlerInterface
{
  public:
    virtual ~DBusHandlerInterface() = default;

    virtual std::string getService(const char* path,
                                   const char* interface) const = 0;
    virtual GetSubTreeResponse
        getSubtree(const std::string& path, int depth,
                   const std::vector<std::string>& ifaceList) const = 0;

    virtual void setDbusProperty(const DBusMapping& dBusMap,
                                 const PropertyValue& value) const = 0;

    virtual PropertyValue
        getDbusPropertyVariant(const char* objPath, const char* dbusProp,
                               const char* dbusInterface) const = 0;
};

/**
 *  @class DBusHandler
 *
 *  Wrapper class to handle the D-Bus calls
 *
 *  This class contains the APIs to handle the D-Bus calls
 *  to cater the response from spdm responders.
 *  A class is created to mock the apis in the test cases
 */
class DBusHandler : public DBusHandlerInterface
{
  public:
    /** @brief Get the bus connection. */
    static auto& getBus()
    {
        static auto bus = sdbusplus::bus::new_default();
        return bus;
    }

    /**
     *  @brief Get the DBUS Service name for the input dbus path
     *
     *  @param[in] path - DBUS object path
     *  @param[in] interface - DBUS Interface
     *
     *  @return std::string - the dbus service name
     *
     *  @throw sdbusplus::exception::exception when it fails
     */
    std::string getService(const char* path,
                           const char* interface) const override;

    /**
     *  @brief Get the Subtree response from the mapper
     *
     *  @param[in] path - DBUS object path
     *  @param[in] depth - Search depth
     *  @param[in] ifaceList - list of the interface that are being
     *                         queried from the mapper
     *
     *  @return GetSubTreeResponse - the mapper subtree response
     *
     *  @throw sdbusplus::exception::exception when it fails
     */
    GetSubTreeResponse
        getSubtree(const std::string& path, int depth,
                   const std::vector<std::string>& ifaceList) const override;

    /** @brief Get property(type: variant) from the requested dbus
     *
     *  @param[in] objPath - The Dbus object path
     *  @param[in] dbusProp - The property name to get
     *  @param[in] dbusInterface - The Dbus interface
     *
     *  @return The value of the property(type: variant)
     *
     *  @throw sdbusplus::exception::exception when it fails
     */
    PropertyValue
        getDbusPropertyVariant(const char* objPath, const char* dbusProp,
                               const char* dbusInterface) const override;

    /** @brief The template function to get property from the requested dbus
     *         path
     *
     *  @tparam Property - Excepted type of the property on dbus
     *
     *  @param[in] objPath - The Dbus object path
     *  @param[in] dbusProp - The property name to get
     *  @param[in] dbusInterface - The Dbus interface
     *
     *  @return The value of the property
     *
     *  @throw sdbusplus::exception::exception when dbus request fails
     *         std::bad_variant_access when \p Property and property on dbus do
     *         not match
     */
    template <typename Property>
    auto getDbusProperty(const char* objPath, const char* dbusProp,
                         const char* dbusInterface)
    {
        auto variantValue =
            getDbusPropertyVariant(objPath, dbusProp, dbusInterface);
        return std::get<Property>(variantValue);
    }

    /** @brief Set Dbus property
     *
     *  @param[in] dBusMap - Object path, property name, interface and property
     *                       type for the D-Bus object
     *  @param[in] value - The value to be set
     *
     *  @throw sdbusplus::exception::exception when it fails
     */
    void setDbusProperty(const DBusMapping& dBusMap,
                         const PropertyValue& value) const override;
};

/** @brief Fetch parent D-Bus object based on pathname
 *
 *  @param[in] dbusObj - child D-Bus object
 *
 *  @return std::string - the parent D-Bus object path
 */
inline std::string findParent(const std::string& dbusObj)
{
    fs::path p(dbusObj);
    return p.parent_path().string();
}

/** @brief Convert the buffer to std::string
 *
 *  If there are characters that are not printable characters, it is replaced
 *  with space(0x20).
 *
 *  @param[in] var - pointer to data and length of the data
 *
 *  @return std::string equivalent of variable field
 */
std::string toString(const struct variable_field& var);

} // namespace utils
} // namespace spdmd
