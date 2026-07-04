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

// End-to-end test for CompositeOrchestrator against MockAttester. Builds
// the tag-602 bundle and runs the verifier-side check:
// for every signed submods entry, recompute SHA-384 over the matching
// detached Claims-Set and compare to the signed digest.

#include "../composite/cbor_test_util.hpp"
#include "composite/bundle_assembler.hpp"
#include "composite/composite_orchestrator.hpp"
#include "composite/submodule_digest.hpp"
#include "mock_attester/mock_attester.hpp"

#include <array>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace spdmd
{
namespace
{

composite::CollectedEvidence spdmDev(const std::string& env, std::uint8_t eid,
                                     std::uint8_t fill)
{
    composite::CollectedEvidence e;
    e.environmentId = env;
    e.eid = eid;
    e.success = true;
    e.pattern = composite::EvidencePattern::SpdmMeasurements;
    e.signedMeasurements = {fill, std::uint8_t(fill + 1), 0x03};
    e.certChainSpdm = {0xAA, fill};
    return e;
}

composite::CollectedEvidence failedDev(const std::string& env, std::uint8_t eid)
{
    composite::CollectedEvidence e;
    e.environmentId = env;
    e.eid = eid;
    e.success = false;
    e.errorMsg = "collection failed";
    return e;
}

std::array<std::uint8_t, 32> nonce(std::uint8_t v)
{
    std::array<std::uint8_t, 32> n{};
    n.fill(v);
    return n;
}

TEST(CompositeOrchestrator, ProducesBundleAllSuccess)
{
    mock_attester::MockAttester att;
    CompositeOrchestrator orch(att);

    std::vector<composite::CollectedEvidence> evs{
        spdmDev("env.gpu.0", 13, 0x10),
        spdmDev("env.nic.0", 64, 0x20),
    };
    auto n = nonce(0x01);
    auto res = orch.produce(n, evs);

    ASSERT_TRUE(res.success) << res.errorMsg;
    EXPECT_EQ(res.status.totalDevices, 2u);
    EXPECT_EQ(res.status.devicesSucceeded, 2u);
    EXPECT_EQ(res.status.devicesFailed, 0u);
    EXPECT_TRUE(res.status.tokenProduced);
    EXPECT_EQ(res.status.toStatusString(), "Success");
    EXPECT_EQ(res.status.platformAttesterStatus, "SoftwareMock");
    EXPECT_FALSE(res.bundle.empty());
}

TEST(CompositeOrchestrator, PartialSuccessExcludesFailedDevice)
{
    mock_attester::MockAttester att;
    CompositeOrchestrator orch(att);

    std::vector<composite::CollectedEvidence> evs{
        spdmDev("env.gpu.0", 13, 0x10),
        failedDev("env.nic.0", 64),
    };
    auto n = nonce(0x02);
    auto res = orch.produce(n, evs);

    ASSERT_TRUE(res.success) << res.errorMsg;
    EXPECT_EQ(res.status.devicesSucceeded, 1u);
    EXPECT_EQ(res.status.devicesFailed, 1u);
    EXPECT_EQ(res.status.toStatusString(), "PartialSuccess");

    // The failed device must appear in neither submods nor the detached
    // Claims-Set map.
    auto bundle = cbortest::decode(res.bundle);
    auto csMap = bundle->tagged->array[1];
    EXPECT_TRUE(csMap->atText("env.gpu.0"));
    EXPECT_EQ(csMap->atText("env.nic.0"), nullptr);
}

// The core the composite attestation profile step-7 verifier check.
TEST(CompositeOrchestrator, SubmodDigestsMatchDetachedClaimsSets)
{
    mock_attester::MockAttester att;
    CompositeOrchestrator orch(att);

    std::vector<composite::CollectedEvidence> evs{
        spdmDev("env.gpu.0", 13, 0x10),
        spdmDev("env.nic.0", 64, 0x20),
        spdmDev("env.cpu.0", 29, 0x30),
    };
    auto n = nonce(0x07);
    auto res = orch.produce(n, evs);
    ASSERT_TRUE(res.success) << res.errorMsg;

    // Decode bundle: tag-602 [ main-token (bstr), { env => bstr.cbor cs } ].
    auto bundle = cbortest::decode(res.bundle);
    ASSERT_TRUE(bundle->isTag());
    ASSERT_EQ(bundle->tag, composite::kCborTagDetachedEatBundle);
    auto mainTokenBytes = bundle->tagged->array[0]->bytes;
    auto csMap = bundle->tagged->array[1];

    // Decode the signed EAT to read submods (266).
    auto cwt = cbortest::decode(mainTokenBytes);
    auto payload = cwt->tagged->tagged->array[2]->bytes;
    auto claims = cbortest::decode(payload);
    auto submods = claims->atInt(266);
    ASSERT_TRUE(submods && submods->isMap());
    ASSERT_EQ(submods->map.size(), 3u);

    // For each submod, recompute the digest over the detached Claims-Set.
    for (const auto& [k, v] : submods->map)
    {
        ASSERT_TRUE(k->isText());
        const std::string& env = k->text;
        ASSERT_TRUE(v->isArray());
        ASSERT_EQ(v->array.size(), 2u);
        EXPECT_EQ(v->array[0]->ival, composite::kCoseAlgSha384);
        const auto& signedDigest = v->array[1]->bytes;

        auto detached = csMap->atText(env);
        ASSERT_TRUE(detached && detached->isBytes())
            << "missing detached claims-set for " << env;

        auto recomputed = composite::sha384(detached->bytes);
        EXPECT_EQ(
            std::vector<std::uint8_t>(recomputed.begin(), recomputed.end()),
            signedDigest)
            << "digest mismatch for " << env;
    }
}

TEST(CompositeOrchestrator, NonceBoundIntoSignedToken)
{
    mock_attester::MockAttester att;
    CompositeOrchestrator orch(att);
    std::vector<composite::CollectedEvidence> evs{
        spdmDev("env.gpu.0", 13, 0x10)};
    auto n = nonce(0x9C);
    auto res = orch.produce(n, evs);
    ASSERT_TRUE(res.success) << res.errorMsg;

    auto bundle = cbortest::decode(res.bundle);
    auto cwt = cbortest::decode(bundle->tagged->array[0]->bytes);
    auto claims = cbortest::decode(cwt->tagged->tagged->array[2]->bytes);
    auto nonceClaim = claims->atInt(10);
    ASSERT_TRUE(nonceClaim && nonceClaim->isBytes());
    EXPECT_EQ(nonceClaim->bytes, std::vector<std::uint8_t>(n.begin(), n.end()));
}

} // namespace
} // namespace spdmd
