#pragma once

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
using Interface = std::string;
using Property = std::string;
using Value =
    std::variant<bool, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t,
                 uint64_t, double, std::string, std::vector<uint8_t>>;

using PropertyMap = std::map<Property, Value>;
using InterfaceMap = std::map<Interface, PropertyMap>;
using ObjectValueTree = std::map<sdbusplus::message::object_path, InterfaceMap>;

} // namespace dbus

} // namespace spdmd
