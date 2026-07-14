/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
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

#include "spdmd_app_context.hpp"

#include <spdmcpp/dbus_impl_responder.hpp>

namespace spdmd
{
namespace dbus_api
{

/**
 * @struct Responder creation parameters
 */
struct ResponderArgs
{
    uint8_t eid;
    std::string uuid;
    std::string medium;
    std::string bindingType;
    sdbusplus::object_path mctpPath;
    sdbusplus::object_path inventoryPath;
    std::string socketPath;
};

class Responder : public spdmcpp::Responder
{
  public:
    Responder(SpdmdAppContext& appCtx, const std::string& path, uint8_t eid,
              const sdbusplus::object_path& mctpPath,
              const sdbusplus::object_path& inventoryPath,
              std::string transportMedium, std::string bindingType,
              std::string socketPath) :
        spdmcpp::Responder(
            appCtx.getConn(), appCtx.getIo(), appCtx.context, appCtx.getLog(),
            [&appCtx](const std::string& message) {
                appCtx.reportError(message);
            },
            path, eid, mctpPath, inventoryPath, std::move(transportMedium),
            std::move(bindingType), std::move(socketPath),
            appCtx.getPropertyByEid<bool>(eid, "visible").value_or(true))
    {}
};

} // namespace dbus_api
} // namespace spdmd
