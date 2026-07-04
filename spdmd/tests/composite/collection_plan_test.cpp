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

// Unit tests for CollectionPlan — env.* validation, locator resolution,
// fallback, and config JSON parsing.

#include "composite/collection_plan.hpp"

#include <string>

#include <gtest/gtest.h>

namespace spdmd::composite
{
namespace
{

TEST(CollectionPlan, EnvIdValidation)
{
    EXPECT_TRUE(CollectionPlan::isValidEnvId("env"));
    EXPECT_TRUE(CollectionPlan::isValidEnvId("env.gpu.0"));
    EXPECT_TRUE(CollectionPlan::isValidEnvId("env.nic.primary"));
    EXPECT_TRUE(CollectionPlan::isValidEnvId("env.m2.boot"));
    EXPECT_TRUE(CollectionPlan::isValidEnvId("env.pcie.4"));

    EXPECT_FALSE(CollectionPlan::isValidEnvId(""));
    EXPECT_FALSE(CollectionPlan::isValidEnvId("gpu.0"));     // no env prefix
    EXPECT_FALSE(CollectionPlan::isValidEnvId("ENV.gpu.0")); // uppercase
    EXPECT_FALSE(CollectionPlan::isValidEnvId("env.GPU"));   // uppercase
    EXPECT_FALSE(CollectionPlan::isValidEnvId("env."));      // trailing dot
    EXPECT_FALSE(CollectionPlan::isValidEnvId("env..0"));    // empty comp
    EXPECT_FALSE(CollectionPlan::isValidEnvId("env.gpu-0")); // bad char
    EXPECT_FALSE(CollectionPlan::isValidEnvId(
        "env.this.identifier.is.way.too.long.to.be.valid.because.over."
        "sixtyfour")); // > 64 bytes
}

TEST(CollectionPlan, ResolveByEid)
{
    CollectionPlan p;
    CollectionPlan::Entry e;
    e.env = "env.gpu.0";
    e.mctpEid = 13;
    ASSERT_TRUE(p.addEntry(e));

    EXPECT_EQ(p.resolveByEid(13), "env.gpu.0");
    EXPECT_EQ(p.resolveByEid(99), "env.unknown.99");
}

TEST(CollectionPlan, AddEntryRejectsInvalidEnv)
{
    CollectionPlan p;
    CollectionPlan::Entry e;
    e.env = "not-an-env";
    e.mctpEid = 1;
    EXPECT_FALSE(p.addEntry(e));
    EXPECT_EQ(p.size(), 0u);
}

TEST(CollectionPlan, MultiPredicateMatch)
{
    CollectionPlan p;
    CollectionPlan::Entry e;
    e.env = "env.nic.0";
    e.mctpEid = 64;
    e.pcieBdf = "0000:17:00.0";
    ASSERT_TRUE(p.addEntry(e));

    CollectionPlan::Locator match;
    match.eid = 64;
    match.pcieBdf = "0000:17:00.0";
    EXPECT_EQ(p.resolve(match), "env.nic.0");

    // EID matches but BDF differs -> no match -> fallback.
    CollectionPlan::Locator mismatch;
    mismatch.eid = 64;
    mismatch.pcieBdf = "0000:18:00.0";
    EXPECT_EQ(p.resolve(mismatch), "env.unknown.64");
}

TEST(CollectionPlan, FromJsonValid)
{
    const std::string json = R"({
        "platformCorimLocator": "tag:example.com,2026:platform-corim:v7",
        "environments": [
            { "env": "env.gpu.0", "match": { "mctpEid": 13 } },
            { "env": "env.nic.0", "match": { "mctpEid": 64 } },
            { "env": "env.rot",   "match": { "mctpEid": 12 } }
        ]
    })";

    std::string err;
    auto plan = CollectionPlan::fromJson(json, err);
    ASSERT_TRUE(plan.has_value()) << err;
    EXPECT_EQ(plan->size(), 3u);
    ASSERT_TRUE(plan->platformCorimLocator().has_value());
    EXPECT_EQ(*plan->platformCorimLocator(),
              "tag:example.com,2026:platform-corim:v7");
    EXPECT_EQ(plan->resolveByEid(13), "env.gpu.0");
    EXPECT_EQ(plan->resolveByEid(12), "env.rot");
    EXPECT_EQ(plan->resolveByEid(7), "env.unknown.7");
}

TEST(CollectionPlan, FromJsonRejectsInvalidEnv)
{
    const std::string json = R"({
        "environments": [ { "env": "BAD", "match": { "mctpEid": 1 } } ]
    })";
    std::string err;
    auto plan = CollectionPlan::fromJson(json, err);
    EXPECT_FALSE(plan.has_value());
    EXPECT_FALSE(err.empty());
}

TEST(CollectionPlan, FromJsonEmptyPlanIsValid)
{
    std::string err;
    auto plan = CollectionPlan::fromJson("{}", err);
    ASSERT_TRUE(plan.has_value()) << err;
    EXPECT_EQ(plan->size(), 0u);
    EXPECT_EQ(plan->resolveByEid(5), "env.unknown.5");
}

TEST(CollectionPlan, FromJsonRejectsNonObject)
{
    std::string err;
    EXPECT_FALSE(CollectionPlan::fromJson("[]", err).has_value());
    EXPECT_FALSE(CollectionPlan::fromJson("not json", err).has_value());
}

} // namespace
} // namespace spdmd::composite
