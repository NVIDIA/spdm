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

#include "composite_orchestrator.hpp"

#include "bundle_assembler.hpp"
#include "claims_set_builder.hpp"
#include "submodule_digest.hpp"

#include <algorithm>
#include <exception>
#include <utility>

namespace spdmd
{

std::string CompositeStatus::toStatusString() const
{
    if (!tokenProduced)
    {
        return "Error";
    }
    if (devicesFailed == 0)
    {
        return "Success";
    }
    return "PartialSuccess";
}

CompositeOrchestrator::CompositeOrchestrator(PlatformAttester& a, bool typed) :
    attester(a), typedClaimsSets(typed)
{}

CompositeOrchestrator::Result CompositeOrchestrator::produce(
    std::span<const std::uint8_t, composite::kNonceLen> nonce,
    std::span<const composite::CollectedEvidence> evidences,
    std::optional<std::string> corimLoc)
{
    using composite::buildClaimsSet;
    using composite::CompositeEatRequest;
    using composite::makeSubmoduleRecord;
    using composite::SubmoduleRecord;

    Result out;
    out.status.totalDevices = evidences.size();

    // 1. Build detached Claims-Sets + digests for successful devices.
    std::vector<std::pair<std::string, std::vector<std::uint8_t>>>
        detachedClaimsSets;
    std::vector<SubmoduleRecord> records;

    for (const auto& ev : evidences)
    {
        if (!ev.success)
        {
            ++out.status.devicesFailed;
            out.status.deviceFailures.push_back(
                {ev.eid, ev.environmentId,
                 ev.errorMsg.empty() ? "collection failed" : ev.errorMsg});
            continue;
        }
        try
        {
            std::vector<std::uint8_t> cs = buildClaimsSet(ev, typedClaimsSets);
            records.push_back(makeSubmoduleRecord(ev.environmentId, cs));
            detachedClaimsSets.emplace_back(ev.environmentId, std::move(cs));
            ++out.status.devicesSucceeded;
        }
        catch (const std::exception& e)
        {
            ++out.status.devicesFailed;
            out.status.deviceFailures.push_back(
                {ev.eid, ev.environmentId, e.what()});
            // A malformed device is treated as a collection failure; it
            // contributes no Claims-Set and no submod.
        }
    }

    // 2. Ask the Lead Attester to build the composite EAT.
    CompositeEatRequest req;
    std::copy(nonce.begin(), nonce.end(), req.nonce.begin());
    req.deviceRecords = records;
    req.platformCorimLocator = std::move(corimLoc);

    composite::CompositeEatResponse attResult =
        attester.generateCompositeEat(req);

    out.status.platformAttesterStatus =
        std::string{toString(attester.getStatus())};
    out.status.attesterErrorMsg = attResult.errorMsg;

    if (!attResult.success)
    {
        out.success = false;
        out.errorMsg = "attester failed: " + attResult.errorMsg;
        return out;
    }
    out.status.tokenProduced = true;

    // 3. Assemble the tag-602 bundle.
    out.bundle =
        composite::assembleBundle(attResult.compositeEat, detachedClaimsSets);
    out.success = true;
    return out;
}

} // namespace spdmd
