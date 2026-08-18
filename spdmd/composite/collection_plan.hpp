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

// CollectionPlan — maps discovered SPDM endpoints to stable env.* target
// environment identifiers.
//
// The submods map key is an operator-owned env.* topology label, NOT the
// MCTP EID. This class resolves a runtime locator (MCTP EID, Redfish URI,
// PCIe BDF, I2C address) to an env.* key using an explicit config plan,
// falling back to env.unknown.<eid> when no entry matches. The collection
// plan is operator data derived from (but not authoritative to) the
// Platform CoRIM.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace spdmd::composite
{

class CollectionPlan
{
  public:
    /// One environment mapping rule. The first rule whose populated
    /// match predicates all match a discovered endpoint wins.
    struct Entry
    {
        std::string env; // env.* target id
        std::optional<std::uint8_t> mctpEid;
        std::optional<std::string> redfishUri;
        std::optional<std::string> pcieBdf;
        std::optional<std::string> i2cAddr;
    };

    /// Locator attributes of a discovered endpoint to resolve.
    struct Locator
    {
        std::uint8_t eid = 0;
        std::optional<std::string> redfishUri;
        std::optional<std::string> pcieBdf;
        std::optional<std::string> i2cAddr;
    };

    /// Validate an env.* identifier per the composite attestation profile:
    /// lowercase ASCII, dot-separated, first component "env", at least one
    /// target component, <= 64 bytes.
    static bool isValidEnvId(std::string_view id);

    /// Add a mapping rule. Returns false if env is invalid.
    bool addEntry(Entry e);

    /// Resolve a locator to an env.* key. Returns the first matching
    /// entry's env, else "env.unknown.<eid>".
    std::string resolve(const Locator& loc) const;

    /// Convenience: resolve by EID only.
    std::string resolveByEid(std::uint8_t eid) const;

    /// Optional Platform CoRIM locator hint for the whole platform.
    const std::optional<std::string>& platformCorimLocator() const
    {
        return corimLocator;
    }
    void setPlatformCorimLocator(std::string locator)
    {
        corimLocator = std::move(locator);
    }

    std::size_t size() const
    {
        return entries.size();
    }

    /// Parse a /etc/spdmd/composite.json document. On error returns
    /// std::nullopt and sets @p err. Note: no eat_profile is read — the
    /// Lead Attester (RoT) owns the composite EAT profile.
    static std::optional<CollectionPlan> fromJson(std::string_view json,
                                                  std::string& err);

  private:
    std::vector<Entry> entries;
    std::optional<std::string> corimLocator;
};

struct ParsedCompositeConfig
{
    CollectionPlan plan;
    std::vector<std::uint8_t> skipDevices;
    bool allowUnknownEnvironments = false;
};

std::optional<ParsedCompositeConfig>
    parseCompositeConfig(std::string_view json, std::string& err);

} // namespace spdmd::composite
