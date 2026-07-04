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

// Shared types for BMC-side composite attestation.
//
// Per the BMC-mediated platform composite attestation design: the BMC's SPDM
// daemon collects nonce-bound per-device evidence, packages each device's
// evidence as a deterministic CBOR detached Claims-Set, and relays a
// single digest per device to the Lead Attester (BMC RoT). The Lead
// Attester builds and signs the composite EAT (inserting eat_profile,
// ueid, and measurements itself) and returns it; the BMC then assembles
// the tag-602 Detached EAT Bundle.
//
// These structs define the boundary objects exchanged between the
// collector (orchestrator), the Lead Attester (PlatformAttester), and the
// bundle assembler. The BMC never authors EAT claims, never holds the
// signing key, and never appraises evidence.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace spdmd::composite
{

/// COSE Algorithms registry id for SHA-384 used as the detached
/// Claims-Set digest algorithm. Independent of the SPDM-negotiated hash.
inline constexpr int kCoseAlgSha384 = -43;

/// Size of a SHA-384 digest in bytes.
inline constexpr std::size_t kSha384Len = 48;

/// Size of the verifier nonce in bytes.
inline constexpr std::size_t kNonceLen = 32;

/// SPDM MeasurementSpecification values used by ALGORITHMS and
/// measurement blocks. DMTF measurements are bit 0 in published SPDM;
/// the EAT value is the proposed bit used by the SPDM EAT work item.
inline constexpr std::uint8_t kSpdmMeasurementSpecDmtf = 1U << 0U;
inline constexpr std::uint8_t kSpdmMeasurementSpecEat = 1U << 1U;

/// The form of evidence a device produced. The collector picks the
/// retrieval method; the resulting Claims-Set schema follows from it.
enum class EvidencePattern
{
    /// Pattern A / C — SPDM signed measurements (+ optional Concise
    /// Evidence carried in the measurement blocks; not parsed here).
    SpdmMeasurements,
    /// Pattern B — a nonce-bound device EAT.
    DeviceEat,
};

inline bool hasEatMeasurementSpecification(std::uint8_t spec)
{
    return (spec & kSpdmMeasurementSpecEat) != 0;
}

inline EvidencePattern selectEvidencePattern(std::uint8_t spec,
                                             bool hasDeviceEatToken)
{
    if (hasEatMeasurementSpecification(spec) && hasDeviceEatToken)
    {
        return EvidencePattern::DeviceEat;
    }
    return EvidencePattern::SpdmMeasurements;
}

/// Per-device evidence collected by the BMC, stored verbatim. The
/// collector never parses measurement-block content.
struct CollectedEvidence
{
    /// env.* target environment identifier (becomes the submod key).
    std::string environmentId;

    /// MCTP EID — diagnostic only, never a submod key.
    std::uint8_t eid = 0;

    /// Whether per-device SPDM collection succeeded. Failed devices
    /// contribute no Claims-Set and no submod.
    bool success = false;
    std::string errorMsg;

    EvidencePattern pattern = EvidencePattern::SpdmMeasurements;

    // --- Pattern A / C inputs ---
    /// Redfish/SPDM SignedMeasurements value, verbatim.
    std::vector<std::uint8_t> signedMeasurements;
    /// Raw reassembled SPDM certificate-chain object (not PEM).
    std::vector<std::uint8_t> certChainSpdm;
    /// Observed VCA transcript; required for SPDM 1.0/1.1, omitted for
    /// 1.2+. Included only when @ref includeVca is true.
    std::vector<std::uint8_t> vca;
    bool includeVca = false;

    // --- Pattern B inputs ---
    /// Token format string, e.g. "application/eat+cwt".
    std::string deviceTokenFormat;
    /// Device EAT token bytes, verbatim.
    std::vector<std::uint8_t> deviceToken;
};

/// One detached-submodule-digest record: the only per-device value the
/// BMC sends to the Lead Attester. SHA-384 over the encoded Claims-Set.
struct SubmoduleRecord
{
    std::string environmentId;      // env.* submod key
    int hashAlgId = kCoseAlgSha384; // COSE alg id
    std::array<std::uint8_t, kSha384Len> digest{};
};

/// A Lead-Attester (RoT/BMC) measurement entry carried in EAT claim 273.
/// Authored entirely by the Lead Attester; the mock backend fills it.
struct LeadAttesterMeasurement
{
    std::uint64_t contentFormat = 0; // CoAP Content-Format
    std::vector<std::uint8_t> value; // opaque payload bytes
};

/// Request handed to the Lead Attester. Note: no eat_profile — the RoT
/// owns and inserts the composite EAT profile, ueid, and measurements.
struct CompositeEatRequest
{
    std::array<std::uint8_t, kNonceLen> nonce{};
    std::vector<SubmoduleRecord> deviceRecords;
    /// Optional Platform CoRIM locator hint (signed as metadata only).
    std::optional<std::string> platformCorimLocator;
};

/// Response returned by the Lead Attester: the signed composite EAT only
/// (NOT the tag-602 bundle, which the BMC assembles).
struct CompositeEatResponse
{
    std::vector<std::uint8_t> compositeEat; // CWT(COSE_Sign1) bytes
    bool success = false;
    std::string errorMsg;
};

} // namespace spdmd::composite
