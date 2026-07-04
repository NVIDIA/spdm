/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION &
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

// DbusImplComposite — D-Bus producer for the composite EAT bundle.
//
// Exposes xyz.openbmc_project.SPDM.CompositeEATBundle on
// /xyz/openbmc_project/SPDM/CompositeEATBundle :
//
//   Generate(nonce: ay)  start collection (single-flight; EBUSY if busy)
//   Status:    s         Idle / InProgress / Ready / Error
//   Bundle:    ay        raw tag-602 Detached EAT Bundle (valid when Ready)
//
// Collection is fanned out across active per-device Responders; each
// registers a completion callback that decrements a pending counter.
// When all report (or the overall timer fires) evidence is snapshotted,
// mapped to env.* via the CollectionPlan, packaged as detached
// Claims-Sets, and handed to CompositeOrchestrator. The single nonce
// binds the whole collection. bmcweb only triggers and reads bytes.
//
// Depends on the concrete dbus_api::Responder from the per-device SPDM
// porting work, so it sits with the per-device integration layer. The
// vendor-
// neutral core (CompositeOrchestrator + composite/*) is upstream.

#pragma once

#include "composite/collection_plan.hpp"
#include "composite/composite_orchestrator.hpp"
#include "dbus_impl_responder.hpp"
#include "platform_attester.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace spdmd
{

struct CompositeConfig
{
    std::uint32_t perDeviceTimeoutMs = 30000;
    std::uint32_t overallTimeoutMs = 120000;
    std::vector<std::uint8_t> skipDevices;
    bool allowUnknownEnvironments = false;
    composite::CollectionPlan plan; // env.* mapping + CoRIM locator
};

/// Load CompositeConfig from a composite.json path. Missing/invalid file
/// yields defaults. Unknown env.* mappings are rejected unless explicitly
/// allowed by config.
CompositeConfig loadCompositeConfig(const std::string& path);

class DbusImplComposite
{
  public:
    static constexpr const char* objectPath =
        "/xyz/openbmc_project/SPDM/CompositeEATBundle";
    static constexpr const char* interfaceName =
        "xyz.openbmc_project.SPDM.CompositeEATBundle";

    DbusImplComposite(
        sdbusplus::asio::object_server& objServer,
        CompositeOrchestrator& orchestrator,
        std::vector<std::shared_ptr<dbus_api::Responder>>& responders,
        boost::asio::io_context& ioCtx, CompositeConfig config);

    ~DbusImplComposite();

    DbusImplComposite(const DbusImplComposite&) = delete;
    DbusImplComposite& operator=(const DbusImplComposite&) = delete;
    DbusImplComposite(DbusImplComposite&&) = delete;
    DbusImplComposite& operator=(DbusImplComposite&&) = delete;

  private:
    void startCollection(const std::vector<std::uint8_t>& nonce);
    void onDeviceComplete(std::uint8_t eid, bool success);
    composite::CollectedEvidence makeEvidence(dbus_api::Responder& resp,
                                              bool success) const;
    void finalize();
    bool isSkipped(std::uint8_t eid) const;
    void publishStatus(const std::string& s);

    sdbusplus::asio::object_server& objServer;
    std::shared_ptr<sdbusplus::asio::dbus_interface> iface;
    CompositeOrchestrator& orchestrator;
    std::vector<std::shared_ptr<dbus_api::Responder>>& responders;
    boost::asio::io_context& ioCtx;
    CompositeConfig config;

    std::string statusStr = "Idle";
    std::vector<std::uint8_t> bundle;

    bool inProgress = false;
    std::size_t pending = 0;
    std::array<std::uint8_t, 32> nonce{};
    std::array<bool, 256> done{};
    std::vector<std::shared_ptr<dbus_api::Responder>> active;
    std::vector<composite::CollectedEvidence> evidences;
    std::array<std::unique_ptr<boost::asio::steady_timer>, 256> perDevTimers;
    boost::asio::steady_timer overallTimer;
};

} // namespace spdmd
