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

// PlatformAttester - vendor-neutral Lead Attester interface.
//
// This is the contract between the SPDM daemon and a platform-specific
// backend RoT / Lead Attester. The SPDM daemon sends a
// CompositeEatRequest carrying the verifier-supplied nonce, per-device
// submodule digests, and an optional Platform CoRIM locator hint. The
// PlatformAttester backend generates the Composite EAT and returns it to
// the SPDM daemon.
//
// Vendor integration guidance:
//   1. Implement PlatformAttester in a platform-specific backend.
//   2. Translate CompositeEatRequest into the RoT command/protocol.
//   3. Let the RoT generate and return the Composite EAT bytes.
//   4. Report backend availability through PlatformAttesterStatus.
//
// The transport between the BMC and the platform attester is deliberately
// outside this interface. It may be a mailbox, MCTP VDM, or any other
// platform-specific mechanism. Backends are selected by Meson option and
// compile-time gates; the upstream mock backend is for development and
// test only.

#pragma once

#include "composite/types.hpp"

#include <string_view>

namespace spdmd
{

enum class PlatformAttesterStatus
{
    Unavailable,
    Ready,
#ifdef ATTESTER_BACKEND_MOCK
    SoftwareMock,
#endif
};

inline std::string_view toString(PlatformAttesterStatus status)
{
    switch (status)
    {
        case PlatformAttesterStatus::Unavailable:
            return "Unavailable";
        case PlatformAttesterStatus::Ready:
            return "Ready";
#ifdef ATTESTER_BACKEND_MOCK
        case PlatformAttesterStatus::SoftwareMock:
            return "SoftwareMock";
#endif
    }
    return "Unavailable";
}

class PlatformAttester
{
  public:
    virtual ~PlatformAttester() = default;

    /// Generate and return the composite EAT (NOT the tag-602 bundle).
    /// The implementation inserts eat_profile, ueid, platform
    /// measurements, and signing material internally.
    virtual composite::CompositeEatResponse
        generateCompositeEat(const composite::CompositeEatRequest& req) = 0;

    /// Backend availability/mode for diagnostics. This is not an
    /// appraisal result.
    virtual PlatformAttesterStatus getStatus() const = 0;
};

} // namespace spdmd
