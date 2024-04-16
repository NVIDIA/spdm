/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */




#pragma once

#include <systemd/sd-bus.h>
#include <unistd.h>

#include <sdbusplus/bus.hpp>
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

inline std::string toEscapedString(const std::vector<uint8_t>& vec)
{
    constexpr std::array<char, 16> hex{{'0', '1', '2', '3', '4', '5', '6', '7',
                                        '8', '9', 'a', 'b', 'c', 'd', 'e',
                                        'f'}};
    std::string ret;
    ret.reserve(vec.size());
    for (auto ch : vec)
    {
        if (std::isprint(ch))
        {
            ret.push_back(static_cast<char>(ch));
        }
        else
        {
            ret.append("\\x");
            ret.push_back(hex[(ch & 0xF0) >> 4]);
            ret.push_back(hex[(ch & 0x0F)]);
        }
    }
    return ret;
}

inline std::string toBigEndianHexString(const std::vector<uint8_t>& vec)
{
    constexpr std::array<char, 16> hex{{'0', '1', '2', '3', '4', '5', '6', '7',
                                        '8', '9', 'A', 'B', 'C', 'D', 'E',
                                        'F'}};
    std::string ret;
    ret.reserve(2 + vec.size());
    ret.push_back('0');
    ret.push_back('x');
    for (auto ch : vec)
    {
        ret.push_back(hex[(ch & 0xF0) >> 4]);
        ret.push_back(hex[(ch & 0x0F)]);
    }
    return ret;
}

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

/**
 *  @brief Helper struct for getting the Service name from the ObjectMapper
 */
struct ServiceHelper
{
    ServiceHelper() = delete;

    /**
     *  @brief Constructor
     *
     *  @param[in] aPath - DBUS object path, must be a constant literal that's
     * never deallocated
     *  @param[in] anInterface - DBUS Interface, must be a constant literal
     * that's never deallocated
     *  @param[in] adefaultService - DBUS Service to serve as the default in
     * case getService fails
     *
     */
    constexpr ServiceHelper(const char* aPath, const char* anInterface,
                            const char* adefaultService = nullptr) :
        path(aPath),
        interface(anInterface), defaultService(adefaultService)
    {}

    /**
     *  @brief Get the DBUS Service name for the path and interface that was
     * specified in the constructor
     *
     *  @return std::string - the dbus service name
     *
     *  @throw sdbusplus::exception::exception when it fails
     */
#if 1
    // TODO this is a workaround for issues with the
    // xyz.openbmc_project.ObjectMapper throwing "Call failed: path or object
    // not found" instead of returning the correct values (even though the
    // services are running, and it seems to work in qemu)
    std::string getService(sdbusplus::bus::bus& /*bus*/) const
    {
        return defaultService;
    }
#else
    std::string getService(sdbusplus::bus::bus& bus) const
    {
        constexpr auto mapperService = "xyz.openbmc_project.ObjectMapper";
        constexpr auto mapperPath = "/xyz/openbmc_project/object_mapper";
        constexpr auto mapperInterface = "xyz.openbmc_project.ObjectMapper";

        using DbusInterfaceList = std::vector<std::string>;
        std::map<std::string, std::vector<std::string>> mapperResponse;

        auto mapper = bus.new_method_call(mapperService, mapperPath,
                                          mapperInterface, "GetObject");
        mapper.append(path, DbusInterfaceList({interface}));

        auto mapperResponseMsg = bus.call(mapper);
        mapperResponseMsg.read(mapperResponse);
        return mapperResponse.begin()->first;
        // TODO shouldn't this response be cached? though looking at pldm it
        // doesn't seem to be done?
    }
#endif

    /**
     *  @brief Get the DBUS Service name for the path and interface that was
     * specified in the constructor
     *
     *  @return std::string - the dbus service name
     *
     *  @throw sdbusplus::exception::exception when it fails
     */
    std::string getServiceWithFallback(sdbusplus::bus::bus& bus) const
    {
        try
        {
            return getService(bus);
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            if (e.get_errno() == 113 && defaultService)
            {
                std::cerr
                    << "ServiceHelper(" << path << ", "
                    << interface << ") failed to getService() falling back to default: "
                    << defaultService << std::endl;
                return defaultService;
            }
            throw;
        }
    }

    /**
     *  @brief Helper for bus.new_method_call() filling out the Service, Path,
     * Interface parameters
     *  @throw sdbusplus::exception::exception when it fails
     */
    // NOLINTNEXTLINE readability-identifier-naming
    auto new_method_call(sdbusplus::bus::bus& bus, const char* method) const
    {
        return bus.new_method_call(getServiceWithFallback(bus).c_str(), path,
                                   interface, method);
    }

    /**
     *  @brief Helper for bus.new_method_call() filling out the Service, Path,
     * parameters
     *  @throw sdbusplus::exception::exception when it fails
     */
    // NOLINTNEXTLINE readability-identifier-naming
    auto new_method_call(sdbusplus::bus::bus& bus, const char* interface,
                         const char* method) const
    {
        return bus.new_method_call(getServiceWithFallback(bus).c_str(), path,
                                   interface, method);
    }
    /**
     *  @brief Helper for bus.new_method_call() filling out the Service
     * parameter
     *  @throw sdbusplus::exception::exception when it fails
     */
    // NOLINTNEXTLINE readability-identifier-naming
    auto new_method_call(sdbusplus::bus::bus& bus, const char* path,
                         const char* interface, const char* method) const
    {
        return bus.new_method_call(getServiceWithFallback(bus).c_str(), path,
                                   interface, method);
    }

    auto getPath() const
    {
        return path;
    }

    auto getInterface() const
    {
        return interface;
    }
    auto getDefaultService() const
    {
        return defaultService;
    }

    void waitForService(sdbusplus::bus::bus& bus) const
    {
        bool wait = true;
        sdbusplus::bus::match_t match(
            bus,
            sdbusplus::bus::match::rules::nameOwnerChanged(getService(bus)),
            [&wait](sdbusplus::message::message&) { wait = false; });
        auto method = new_method_call(bus, "GetManagedObjects");
        try
        {
            auto reply = bus.call(method);
        }
        catch (sdbusplus::exception::SdBusError& e)
        {
            if (strcmp(e.name(), SD_BUS_ERROR_SERVICE_UNKNOWN) != 0)
            {
                // if we got unexpected error pass it through
                throw;
            }
            // if service is missing we wait for it to show up
            while (wait)
            {
                bus.wait();
                bus.process();
            }
        }
        return;
    }

  private:
    const char* path = nullptr;
    const char* interface = nullptr;
    const char* defaultService = nullptr;
};

} // namespace dbus

} // namespace spdmd
