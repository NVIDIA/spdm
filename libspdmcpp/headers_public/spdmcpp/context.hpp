/*
 * Copyright (C) NVIDIA Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "assert.hpp"
#include "common.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>
#include <vector>
#include <algorithm>

namespace spdmcpp
{

/** @class ContextClass
 *  @brief Class for storing common configuration and interface for multiple
 * ConnectionClasses
 */
class ContextClass
{
  public:
    ContextClass()
    {
        SupportedVersions.push_back(MessageVersionEnum::SPDM_1_0);
        SupportedVersions.push_back(MessageVersionEnum::SPDM_1_1);
        std::sort(SupportedVersions.begin(), SupportedVersions.end(),
                  std::greater());
    }

    /** @brief Registers an IOClass for handling the communication channel
     * (typically socket)
     *  @param[in] io - Object to be used for sending/reading messages,
     * ContextClass does not take ownership and will not deallocate the
     * object
     */
    void registerIo(IOClass& io, TransportMedium transportMedium)
    {
        switch (transportMedium)
        {
        case TransportMedium::PCIe:
            SPDMCPP_ASSERT(!IO_PCIe);
            IO_PCIe = &io;
            break;

        case TransportMedium::SPI:
            SPDMCPP_ASSERT(!IO_SPI);
            IO_SPI = &io;
            break;

        case TransportMedium::I2C:
            SPDMCPP_ASSERT(!IO_I2C);
            IO_I2C = &io;
            break;

        default:
            throw std::invalid_argument("registerIoPcie: wrong transport medium param");
        }
    }

    /** @brief Unregisters the IOClass object, should be called before
     * destroying io
     *  @param[in] transport - the parameter is provided just for verifying
     * correctness (register and unregister calls must match and can't be
     * redundant)
     */
    void unregisterIo(IOClass& io, TransportMedium transportMedium)
    {
        switch (transportMedium)
        {
        case TransportMedium::PCIe:
            SPDMCPP_ASSERT(IO_PCIe == &io);
            IO_PCIe = nullptr;
            break;

        case TransportMedium::SPI:
            SPDMCPP_ASSERT(IO_SPI == &io);
            IO_SPI = nullptr;
            break;

        case TransportMedium::I2C:
            SPDMCPP_ASSERT(IO_I2C == &io);
            IO_I2C = nullptr;
            break;

        default:
            throw std::invalid_argument("unregisterIo: wrong transport medium param");
        }
    }

    /** @brief SPDM versions that we're configured to support
     */
    const std::vector<MessageVersionEnum>& getSupportedVersions() const
    {
        return SupportedVersions;
    }

    IOClass& getIO(TransportMedium medium) const
    {
        switch (medium)
        {
        case TransportMedium::PCIe:
            return *IO_PCIe;

        case TransportMedium::SPI:
            return *IO_SPI;

        case TransportMedium::I2C:
            return *IO_I2C;
        }
        throw std::invalid_argument("getIO: not supported TransportMedium value");
    }

  protected:
    /** @brief SPDM versions that we're configured to support
     */
    std::vector<MessageVersionEnum> SupportedVersions;

    IOClass* IO_PCIe {};
    IOClass* IO_SPI  {};
    IOClass* IO_I2C  {};
};

} // namespace spdmcpp
