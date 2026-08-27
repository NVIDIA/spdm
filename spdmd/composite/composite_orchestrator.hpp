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

// CompositeOrchestrator — vendor-neutral composite attestation core.
//
//   1. For each successfully collected device: build a detached
//      Claims-Set (ClaimsSetBuilder) and compute its digest
//      (SubmoduleDigest) -> SubmoduleRecord keyed by env.*.
//   2. Submit { nonce, device records, optional CoRIM locator } to the
//      Lead Attester, which returns the signed composite EAT.
//   3. Assemble the tag-602 Detached EAT Bundle (BundleAssembler) by
//      pairing the signed EAT with the detached Claims-Sets.
//
// This class has no dependency on D-Bus, sdbusplus, or JSON. The D-Bus
// binding that translates an incoming Redfish/Generate request into a
// call to produce() lives separately with the per-device responder layer.

#pragma once

#include "platform_attester.hpp"
#include "types.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace spdmd
{

/// Aggregate counts + attester status for surfacing a single status
/// string (Idle / Collecting / Success / PartialSuccess / Error).
struct CompositeStatus
{
    struct DeviceFailure
    {
        std::uint8_t eid = 0;
        std::string environmentId;
        std::string errorMsg;
    };

    std::size_t totalDevices = 0;
    std::size_t devicesSucceeded = 0;
    std::size_t devicesFailed = 0;
    bool tokenProduced = false;
    std::string platformAttesterStatus; // Ready / SoftwareMock / Unavailable
    std::string attesterErrorMsg;       // empty if attestation succeeded
    std::vector<DeviceFailure> deviceFailures;

    std::string toStatusString() const;
};

class CompositeOrchestrator
{
  public:
    struct Result
    {
        std::vector<std::uint8_t> bundle; // tag-602 Detached EAT Bundle
        CompositeStatus status;
        bool success = false;
        std::string errorMsg;
    };

    /// @param attester  Lead Attester to delegate signing to.
    /// @param typedClaimsSets  Use CMW-style typed values in SPDM
    ///        Claims-Sets (default off).
    explicit CompositeOrchestrator(PlatformAttester& attester,
                                   bool typedClaimsSets = false);

    /// Produce the composite bundle from collected evidence.
    ///
    /// @param nonce      Verifier nonce (32 bytes).
    /// @param evidences  Per-device evidence, including failures.
    /// @param corimLoc   Optional Platform CoRIM locator hint.
    Result produce(std::span<const std::uint8_t, composite::kNonceLen> nonce,
                   std::span<const composite::CollectedEvidence> evidences,
                   std::optional<std::string> corimLoc = std::nullopt);

  private:
    PlatformAttester& attester;
    bool typedClaimsSets;
};

} // namespace spdmd
