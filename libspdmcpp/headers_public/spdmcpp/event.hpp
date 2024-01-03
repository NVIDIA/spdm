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
#include "context.hpp"

#include <array>
#include <bitset>
#include <iostream>
#include <vector>

namespace spdmcpp
{

/** @class EventClass
 *  @brief Base class for any events like receiving data or timeouts
 */
struct EventClass
{
    EventClass() = default;

    EventClass(const EventClass&) = delete;
    EventClass(EventClass&&) = delete;
    EventClass& operator=(const EventClass&) = delete;
    EventClass& operator=(EventClass&&) = delete;

    virtual ~EventClass() = default;

    template <class T>
    bool is()
    {
        return dynamic_cast<T*>(this) != nullptr;
    }

    template <class T>
    T* getAs()
    {
        return dynamic_cast<T*>(this);
    }
};

struct EventReceiveClass : EventClass
{
    explicit EventReceiveClass(std::vector<uint8_t>& buf) : buffer(buf)
    {}
    ~EventReceiveClass() override = default;

    EventReceiveClass(const EventReceiveClass&) = delete;
    EventReceiveClass(EventReceiveClass&&) = delete;
    EventReceiveClass& operator=(const EventReceiveClass&) = delete;
    EventReceiveClass& operator=(EventReceiveClass&&) = delete;

    std::vector<uint8_t>& buffer;
};

struct EventTimeoutClass : EventClass
{
    EventTimeoutClass() = delete;
    explicit EventTimeoutClass(TransportMedium transportMedium)
        :transportMedium(transportMedium)
    {}
    ~EventTimeoutClass() override = default;

    EventTimeoutClass(const EventTimeoutClass&) = delete;
    EventTimeoutClass(EventTimeoutClass&&) = delete;
    EventTimeoutClass& operator=(const EventTimeoutClass&) = delete;
    EventTimeoutClass& operator=(EventTimeoutClass&&) = delete;

    TransportMedium transportMedium;
};

} // namespace spdmcpp
