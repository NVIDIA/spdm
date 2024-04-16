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

#include "assert.hpp"
#include "common.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <cstring>
#include <iostream>
#include <limits>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <memory>

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
    void registerIo(const std::shared_ptr<IOClass>& io, const std::string& path)
    {
        if (ioContainer.count(path))
        {
            throw std::invalid_argument("registerIoPcie: wrong transport medium param");
        }
        ioContainer[path] = io;
    }

    /** @brief Unregisters the IOClass object, should be called before
     * destroying io
     *  @param[in] transport - the parameter is provided just for verifying
     * correctness (register and unregister calls must match and can't be
     * redundant)
     */
    void unregisterIo(const std::string& path)
    {
        auto it = ioContainer.find(path);
        if (it != ioContainer.end())
        {
            ioContainer.erase(it);
        }
        else
        {
            throw std::invalid_argument("Unable to unregister path " + path);
        }
    }

    /**
     *  @bref Check if path is registered in the IO context
    */
    bool isIOPathRegistered(const std::string& path) const
    {
        return ioContainer.count(path);
    }

    /** @brief SPDM versions that we're configured to support
     */
    const std::vector<MessageVersionEnum>& getSupportedVersions() const
    {
        return SupportedVersions;
    }

    std::shared_ptr<IOClass> getIO(const std::string& path) const
    {
        auto it = ioContainer.find(path);
        if (it != ioContainer.end())
        {
            auto io = it->second;
            if (!io)
            {
                throw std::invalid_argument("Unable to get io class for " + path);
            }
            return io;
        }
        throw std::invalid_argument("Unable to find path " + path);
    }

  protected:
    /** @brief SPDM versions that we're configured to support
     */
    std::vector<MessageVersionEnum> SupportedVersions;

    /** @brief SPDM container with indentifiers */
    std::unordered_map<std::string,std::shared_ptr<IOClass>> ioContainer;
};

} // namespace spdmcpp
