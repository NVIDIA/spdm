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

#include "dbus_impl_composite.hpp"

#include "composite/evidence_builder.hpp"

#include <sdbusplus/exception.hpp>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>

namespace spdmd
{

CompositeConfig loadCompositeConfig(const std::string& path)
{
    CompositeConfig cfg;
    std::ifstream f(path);
    if (!f)
    {
        return cfg; // defaults: empty plan, default timeouts
    }
    std::stringstream ss;
    ss << f.rdbuf();
    std::string err;
    if (auto parsed = composite::parseCompositeConfig(ss.str(), err))
    {
        cfg.plan = std::move(parsed->plan);
        cfg.skipDevices = std::move(parsed->skipDevices);
        cfg.allowUnknownEnvironments = parsed->allowUnknownEnvironments;
    }
    else
    {
        std::cerr << err << " - using defaults\n";
    }
    return cfg;
}

namespace
{} // namespace

DbusImplComposite::DbusImplComposite(
    sdbusplus::asio::object_server& objServer_,
    CompositeOrchestrator& orchestrator_,
    std::vector<std::shared_ptr<dbus_api::Responder>>& responders_,
    boost::asio::io_context& ioCtx_, CompositeConfig config_) :
    objServer(objServer_),
    orchestrator(orchestrator_), responders(responders_), ioCtx(ioCtx_),
    config(std::move(config_)), overallTimer(ioCtx_)
{
    iface = objServer.add_interface(objectPath, interfaceName);
    iface->register_property("Status", statusStr);
    iface->register_property("Bundle", bundle);

    iface->register_method(
        "Generate", [this](const std::vector<std::uint8_t>& n) {
            if (n.size() != 32)
            {
                throw sdbusplus::exception::SdBusError(
                    -EINVAL, "Nonce must be exactly 32 bytes");
            }
            if (inProgress)
            {
                throw sdbusplus::exception::SdBusError(
                    -EBUSY, "Composite generation already in progress");
            }
            startCollection(n);
        });

    iface->initialize();
}

DbusImplComposite::~DbusImplComposite()
{
    if (iface)
    {
        objServer.remove_interface(iface);
    }
}

void DbusImplComposite::publishStatus(const std::string& s)
{
    statusStr = s;
    if (iface)
    {
        iface->set_property("Status", statusStr);
    }
}

bool DbusImplComposite::isSkipped(std::uint8_t eid) const
{
    return std::find(config.skipDevices.begin(), config.skipDevices.end(),
                     eid) != config.skipDevices.end();
}

void DbusImplComposite::startCollection(const std::vector<std::uint8_t>& n)
{
    std::copy(n.begin(), n.end(), nonce.begin());
    evidences.clear();
    active.clear();
    done.fill(false);
    bundle.clear();
    if (iface)
    {
        iface->set_property("Bundle", bundle);
    }

    for (auto& slot : responders)
    {
        if (slot && !isSkipped(slot->getEid()))
        {
            active.push_back(slot);
        }
    }
    if (active.empty())
    {
        publishStatus("Error");
        return;
    }

    pending = active.size();
    inProgress = true;
    publishStatus("InProgress");

    if (config.overallTimeoutMs > 0)
    {
        overallTimer.expires_after(
            std::chrono::milliseconds(config.overallTimeoutMs));
        overallTimer.async_wait([this](const boost::system::error_code& ec) {
            if (ec == boost::asio::error::operation_aborted || !inProgress)
            {
                return;
            }
            for (auto& r : active)
            {
                if (r && !done[r->getEid()])
                {
                    done[r->getEid()] = true;
                    evidences.push_back(makeEvidence(*r, false));
                }
            }
            pending = 0;
            finalize();
        });
    }

    // Collection fans out to all active responders concurrently: every
    // responder is refreshed in parallel and the collection joins when each
    // reports completion (or the overall timer fires). This relies on the
    // transport supporting multiple in-flight SPDM exchanges. For in-kernel
    // AF_MCTP, requests are tagged per peer EID and responses are routed by
    // source EID, without a daemon-side request/response buffer. A transport
    // that couples responses through one shared buffer needs equivalent
    // per-responder isolation before enabling this fan-out.
    for (auto& resp : active)
    {
        const std::uint8_t eid = resp->getEid();
        auto& timer = perDevTimers[eid];
        timer = std::make_unique<boost::asio::steady_timer>(ioCtx);
        timer->expires_after(
            std::chrono::milliseconds(config.perDeviceTimeoutMs));
        timer->async_wait([this, eid](const boost::system::error_code& ec) {
            if (ec != boost::asio::error::operation_aborted && !done[eid])
            {
                onDeviceComplete(eid, false);
            }
        });
        resp->setRefreshCompleteCallback(
            [this](std::uint8_t e, bool ok) { onDeviceComplete(e, ok); });
        std::vector<std::uint8_t> measurementNonce(nonce.begin(), nonce.end());
        resp->refresh(0u, std::move(measurementNonce), {255}, 0u);
    }
}

composite::CollectedEvidence
    DbusImplComposite::makeEvidence(dbus_api::Responder& resp,
                                    bool success) const
{
    const std::uint8_t eid = resp.getEid();
    const std::string environmentId = config.plan.resolveByEid(eid);
    if (!config.allowUnknownEnvironments &&
        composite::isUnknownEnvironmentId(environmentId))
    {
        return composite::makeFailedEvidence(eid, environmentId,
                                             "missing environment mapping");
    }

    composite::EvidenceBuilderInput input;
    input.eid = eid;
    input.environmentId = environmentId;
    input.success = success;
    input.errorMsg = success ? "" : "Refresh failed";

    if (!success)
    {
        // Do not query negotiated SPDM metadata for a responder that failed
        // or timed out: on a refresh that never reached ALGORITHMS the
        // accessors assert. Failed evidence needs none of it.
        return composite::buildCollectedEvidence(input);
    }

    input.spdmVersion = resp.version();
    input.measurementSpecification = resp.measurementSpecification();

    auto sm = resp.signedMeasurements();
    input.signedMeasurements.assign(sm.begin(), sm.end());
    (void)resp.certificateChainDer(input.certificateChainDer, resp.slot());

    const auto& vca = resp.vcaTranscript();
    input.vcaTranscript.assign(vca.begin(), vca.end());

    const auto& deviceEatToken = resp.deviceEatToken();
    input.deviceEatToken.assign(deviceEatToken.begin(), deviceEatToken.end());

    return composite::buildCollectedEvidence(input);
}

void DbusImplComposite::onDeviceComplete(std::uint8_t eid, bool success)
{
    if (!inProgress)
    {
        return;
    }
    if (done[eid])
    {
        return;
    }
    done[eid] = true;
    if (auto& t = perDevTimers[eid])
    {
        boost::system::error_code ec;
        t->cancel(ec);
    }
    for (auto& r : active)
    {
        if (r && r->getEid() == eid)
        {
            evidences.push_back(makeEvidence(*r, success));
            break;
        }
    }
    if (pending > 0)
    {
        --pending;
    }
    if (pending == 0)
    {
        boost::system::error_code ec;
        overallTimer.cancel(ec);
        finalize();
    }
}

void DbusImplComposite::finalize()
{
    auto res = orchestrator.produce(std::span<const std::uint8_t, 32>{nonce},
                                    std::span{evidences},
                                    config.plan.platformCorimLocator());
    for (const auto& failure : res.status.deviceFailures)
    {
        std::cerr << "composite collection failed for "
                  << failure.environmentId << " (EID "
                  << static_cast<unsigned>(failure.eid)
                  << "): " << failure.errorMsg << '\n';
    }
    if (res.success)
    {
        bundle = std::move(res.bundle);
        if (iface)
        {
            iface->set_property("Bundle", bundle);
        }
        publishStatus("Ready");
    }
    else
    {
        bundle.clear();
        if (iface)
        {
            iface->set_property("Bundle", bundle);
        }
        publishStatus("Error");
    }
    inProgress = false;
    for (auto& r : active)
    {
        if (r)
        {
            r->setRefreshCompleteCallback({});
        }
    }
    active.clear();
    evidences.clear();
    for (auto& t : perDevTimers)
    {
        t.reset();
    }
}

} // namespace spdmd
