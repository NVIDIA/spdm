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

#include "collection_plan.hpp"

#include <nlohmann/json.hpp>

#include <cctype>
#include <utility>

namespace spdmd::composite
{

bool CollectionPlan::isValidEnvId(std::string_view id)
{
    if (id.empty() || id.size() > 64)
    {
        return false;
    }
    // Must start with "env" and be either "env" or "env.".
    if (id == "env")
    {
        return true;
    }
    if (id.size() < 5 || id.substr(0, 4) != "env.")
    {
        return false;
    }
    // Lowercase ASCII letters, digits, dot; no leading/trailing/double
    // dots; each component non-empty.
    bool prevDot = false;
    for (std::size_t i = 0; i < id.size(); ++i)
    {
        const char c = id[i];
        if (c == '.')
        {
            if (prevDot)
            {
                return false; // empty component
            }
            prevDot = true;
            continue;
        }
        prevDot = false;
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        if (!ok)
        {
            return false;
        }
    }
    // No trailing dot.
    return id.back() != '.';
}

bool CollectionPlan::addEntry(Entry e)
{
    if (!isValidEnvId(e.env))
    {
        return false;
    }
    entries.push_back(std::move(e));
    return true;
}

std::string CollectionPlan::resolve(const Locator& loc) const
{
    for (const auto& e : entries)
    {
        // An entry matches only if every populated predicate matches.
        if (e.mctpEid && *e.mctpEid != loc.eid)
        {
            continue;
        }
        if (e.redfishUri &&
            (!loc.redfishUri || *e.redfishUri != *loc.redfishUri))
        {
            continue;
        }
        if (e.pcieBdf && (!loc.pcieBdf || *e.pcieBdf != *loc.pcieBdf))
        {
            continue;
        }
        if (e.i2cAddr && (!loc.i2cAddr || *e.i2cAddr != *loc.i2cAddr))
        {
            continue;
        }
        // At least one predicate must be populated to count as a rule.
        if (e.mctpEid || e.redfishUri || e.pcieBdf || e.i2cAddr)
        {
            return e.env;
        }
    }
    return "env.unknown." + std::to_string(static_cast<unsigned>(loc.eid));
}

std::string CollectionPlan::resolveByEid(std::uint8_t eid) const
{
    Locator loc;
    loc.eid = eid;
    return resolve(loc);
}

std::optional<CollectionPlan> CollectionPlan::fromJson(std::string_view json,
                                                       std::string& err)
{
    nlohmann::json doc =
        nlohmann::json::parse(json, nullptr, false /*no exceptions*/);
    if (doc.is_discarded() || !doc.is_object())
    {
        err = "composite.json: not a JSON object";
        return std::nullopt;
    }

    CollectionPlan plan;

    if (auto it = doc.find("platformCorimLocator"); it != doc.end())
    {
        if (!it->is_string())
        {
            err = "composite.json: platformCorimLocator must be a string";
            return std::nullopt;
        }
        plan.setPlatformCorimLocator(it->get<std::string>());
    }

    auto envs = doc.find("environments");
    if (envs == doc.end())
    {
        return plan; // empty plan is valid (everything resolves to fallback)
    }
    if (!envs->is_array())
    {
        err = "composite.json: environments must be an array";
        return std::nullopt;
    }

    for (const auto& item : *envs)
    {
        if (!item.is_object() || !item.contains("env") ||
            !item["env"].is_string())
        {
            err = "composite.json: each environment needs a string 'env'";
            return std::nullopt;
        }
        Entry e;
        e.env = item["env"].get<std::string>();

        if (auto m = item.find("match"); m != item.end() && m->is_object())
        {
            if (auto v = m->find("mctpEid");
                v != m->end() && v->is_number_unsigned())
            {
                e.mctpEid =
                    static_cast<std::uint8_t>(v->get<unsigned>() & 0xFFU);
            }
            if (auto v = m->find("redfishUri"); v != m->end() && v->is_string())
            {
                e.redfishUri = v->get<std::string>();
            }
            if (auto v = m->find("pcieBdf"); v != m->end() && v->is_string())
            {
                e.pcieBdf = v->get<std::string>();
            }
            if (auto v = m->find("i2cAddr"); v != m->end() && v->is_string())
            {
                e.i2cAddr = v->get<std::string>();
            }
        }

        if (!plan.addEntry(std::move(e)))
        {
            err = "composite.json: invalid env id (must be env.* per "
                  "the composite attestation profile)";
            return std::nullopt;
        }
    }

    return plan;
}

} // namespace spdmd::composite
