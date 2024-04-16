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
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/utility/dedup_variant.hpp>

#include <cstdint>
#include <string>
#include <tuple>
#include <vector>

namespace spdmt
{

using DbusInterface = std::string;
using DbusProperty = std::string;
using DbusValue =
    std::variant<bool, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t,
                 uint64_t, double, std::string, std::vector<uint8_t>>;

using DbusPropertyMap = std::map<DbusProperty, DbusValue>;
using DbusInterfaceMap = std::map<DbusInterface, DbusPropertyMap>;
using DbusObjectValueTree =
    std::map<sdbusplus::message::object_path, DbusInterfaceMap>;

/** @brief SPDM type of an MCTP message */
static constexpr uint8_t mctpTypeSPDM = 5;

/** @brief MCTP d-bus interface name  */
static constexpr auto mctpEndpointIntfName =
    "xyz.openbmc_project.MCTP.Endpoint";

/** @brief MCTP d-bus interface, property name EID  */
static constexpr auto mctpEndpointIntfPropertyEid = "EID";

/** @brief MCTP get medium type*/
static constexpr auto mctpEndpointIntfPropertyMediumType = "MediumType";

/** @brief MCTP d-bus interface, property name EID  */
static constexpr auto mctpEndpointIntfPropertySupportedMessageTypes =
    "SupportedMessageTypes";

static constexpr auto inventorySPDMResponderIntfName =
    "xyz.openbmc_project.Inventory.Item.SPDMResponder";

static constexpr auto uuidIntfName = "xyz.openbmc_project.Common.UUID";

static constexpr auto uuidIntfPropertyUUID = "UUID";
//     static constexpr auto mctpEndpointIntfPropertyUUID =
//         "SupportedMessageTypes";

/** @brief MCTP d-bus Binding interface name  */
static constexpr auto mctpBindingIntfName = "xyz.openbmc_project.MCTP.Binding";

/** @brief Return binding type*/
static constexpr auto mctpBindingIntfPropertyBindType = "BindingType";

/** @brief MCTP transport socket interface name */
static constexpr auto mctpUnixSockIntfName = "xyz.openbmc_project.Common.UnixSocket";

/** @brief MCTP transport sock type */
static constexpr auto unixSocketIntfAddressProperty = "Address";


} // namespace spdmt
