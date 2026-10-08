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

// Unit tests for the composite EAT builder — checks the claims map shape
// , submods as detached digests, measurements, the optional
// CoRIM locator, the COSE protected header, Sig_Structure, and the CWT
// envelope tags.

#include "../composite/cbor_test_util.hpp"
#include "mock_attester/eat_builder.hpp"
#include "mock_attester/mock_attester.hpp"

#include <array>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace spdmd::mock_attester::eat
{
namespace
{

using composite::SubmoduleRecord;

std::array<std::uint8_t, 32> nonceFill(std::uint8_t v)
{
    std::array<std::uint8_t, 32> n{};
    n.fill(v);
    return n;
}

SubmoduleRecord recordFor(const std::string& env, std::uint8_t fill)
{
    SubmoduleRecord r;
    r.environmentId = env;
    r.hashAlgId = composite::kCoseAlgSha384;
    r.digest.fill(fill);
    return r;
}

// EAT claim keys.
constexpr std::int64_t kNonce = 10;
constexpr std::int64_t kUeid = 256;
constexpr std::int64_t kProfile = 265;
constexpr std::int64_t kSubmods = 266;
constexpr std::int64_t kMeasurements = 273;
constexpr std::int64_t kCorimId = -75000;

std::vector<std::uint8_t> buildSample(bool withCorim,
                                      std::span<const SubmoduleRecord> recs)
{
    auto nonce = nonceFill(0xAB);
    std::vector<std::uint8_t> ueid{0x01, 0x02, 0x03, 0x04};
    std::vector<LeadAttesterConciseEvidence> meas;
    LeadAttesterConciseEvidence m;
    m.classId = {'m', 'o', 'c', 'k', '-', 'b', 'm', 'c'};
    m.digest.fill(0x38);
    meas.push_back(m);

    std::optional<std::string> corim;
    if (withCorim)
    {
        corim = "tag:example.com,2026:platform-corim:v7";
    }
    return buildCompositeClaims(std::span<const std::uint8_t, 32>{nonce}, ueid,
                                kCompositeEatDraftProfileUri, recs, meas,
                                corim);
}

TEST(EatBuilder, ClaimsTopLevelKeys)
{
    auto recs = std::vector<SubmoduleRecord>{recordFor("env.gpu.0", 0x11)};
    auto claims = buildSample(false, recs);
    auto root = cbortest::decode(claims);
    ASSERT_TRUE(root->isMap());

    // Mandatory: nonce, ueid, profile, submods, measurements.
    auto nonce = root->atInt(kNonce);
    ASSERT_TRUE(nonce && nonce->isBytes());
    EXPECT_EQ(nonce->bytes.size(), 32u);

    auto ueid = root->atInt(kUeid);
    ASSERT_TRUE(ueid && ueid->isBytes());
    EXPECT_EQ(ueid->bytes, (std::vector<std::uint8_t>{0x01, 0x02, 0x03, 0x04}));

    auto profile = root->atInt(kProfile);
    ASSERT_TRUE(profile && profile->isText());
    EXPECT_EQ(profile->text, kCompositeEatDraftProfileUri);

    ASSERT_TRUE(root->atInt(kSubmods));
    ASSERT_TRUE(root->atInt(kMeasurements));
    // No CoRIM locator when not supplied.
    EXPECT_EQ(root->atInt(kCorimId), nullptr);
}

TEST(EatBuilder, SubmodsAreDetachedDigests)
{
    std::vector<SubmoduleRecord> recs{recordFor("env.gpu.0", 0x11),
                                      recordFor("env.nic.0", 0x22)};
    auto claims = buildSample(false, recs);
    auto root = cbortest::decode(claims);
    auto submods = root->atInt(kSubmods);
    ASSERT_TRUE(submods && submods->isMap());
    EXPECT_EQ(submods->map.size(), 2u);

    auto gpu = submods->atText("env.gpu.0");
    ASSERT_TRUE(gpu && gpu->isArray());
    ASSERT_EQ(gpu->array.size(), 2u);
    // [hash-alg, digest]
    EXPECT_EQ(gpu->array[0]->ival, composite::kCoseAlgSha384);
    ASSERT_TRUE(gpu->array[1]->isBytes());
    EXPECT_EQ(gpu->array[1]->bytes.size(), 48u);
    EXPECT_EQ(gpu->array[1]->bytes[0], 0x11);
}

TEST(EatBuilder, MeasurementsAreTcgConciseEvidence)
{
    std::vector<SubmoduleRecord> recs{recordFor("env.rot", 0x33)};
    auto claims = buildSample(false, recs);
    auto root = cbortest::decode(claims);
    auto meas = root->atInt(kMeasurements);
    ASSERT_TRUE(meas && meas->isArray());
    ASSERT_EQ(meas->array.size(), 1u);
    auto entry = meas->array[0];
    ASSERT_TRUE(entry->isArray());
    ASSERT_EQ(entry->array.size(), 2u);
    EXPECT_EQ(entry->array[0]->uarg, kTcgConciseEvidenceContentFormat);
    ASSERT_TRUE(entry->array[1]->isBytes());

    auto document = cbortest::decode(entry->array[1]->bytes);
    auto evidenceTriples = document->atInt(0);
    ASSERT_TRUE(evidenceTriples && evidenceTriples->isMap());
    auto triples = evidenceTriples->atInt(0);
    ASSERT_TRUE(triples && triples->isArray());
    ASSERT_EQ(triples->array.size(), 1u);
    auto triple = triples->array[0];
    ASSERT_TRUE(triple->isArray());
    ASSERT_EQ(triple->array.size(), 2u);

    auto classInfo = triple->array[0]->atInt(0);
    ASSERT_TRUE(classInfo && classInfo->isMap());
    auto classId = classInfo->atInt(0);
    ASSERT_TRUE(classId && classId->isTag());
    EXPECT_EQ(classId->tag, 560u);
    EXPECT_EQ(
        classId->tagged->bytes,
        (std::vector<std::uint8_t>{'m', 'o', 'c', 'k', '-', 'b', 'm', 'c'}));

    auto measurements = triple->array[1];
    ASSERT_TRUE(measurements->isArray());
    ASSERT_EQ(measurements->array.size(), 1u);
    auto measurement = measurements->array[0];
    EXPECT_EQ(measurement->atInt(0)->uarg, 0u);
    auto values = measurement->atInt(1);
    ASSERT_TRUE(values && values->isMap());
    auto digests = values->atInt(2);
    ASSERT_TRUE(digests && digests->isArray());
    ASSERT_EQ(digests->array.size(), 1u);
    auto digest = digests->array[0];
    ASSERT_TRUE(digest->isArray());
    ASSERT_EQ(digest->array.size(), 2u);
    EXPECT_EQ(digest->array[0]->text, "sha-384");
    EXPECT_EQ(digest->array[1]->bytes, (std::vector<std::uint8_t>(48, 0x38)));
}

TEST(EatBuilder, ConciseEvidenceEncodingIsDeterministic)
{
    auto claimsA = buildSample(false, {});
    auto claimsB = buildSample(false, {});
    EXPECT_EQ(claimsA, claimsB);

    auto root = cbortest::decode(claimsA);
    auto evidence = root->atInt(kMeasurements)->array[0]->array[1]->bytes;
    const std::vector<std::uint8_t> expectedPrefix{
        0xA1, 0x00, 0xA1, 0x00, 0x81, 0x82, 0xA1, 0x00, 0xA1, 0x00, 0xD9,
        0x02, 0x30, 0x48, 'm',  'o',  'c',  'k',  '-',  'b',  'm',  'c',
        0x81, 0xA2, 0x00, 0x00, 0x01, 0xA1, 0x02, 0x81, 0x82, 0x67, 's',
        'h',  'a',  '-',  '3',  '8',  '4',  0x58, 0x30};
    ASSERT_GE(evidence.size(), expectedPrefix.size());
    EXPECT_TRUE(std::equal(expectedPrefix.begin(), expectedPrefix.end(),
                           evidence.begin()));
    EXPECT_EQ(std::vector<std::uint8_t>(
                  evidence.begin() + expectedPrefix.size(), evidence.end()),
              (std::vector<std::uint8_t>(48, 0x38)));
}

TEST(EatBuilder, EveryMeasurementUsesConciseEvidence)
{
    auto nonce = nonceFill(0xAB);
    std::vector<std::uint8_t> ueid{0x01};
    std::vector<LeadAttesterConciseEvidence> evidence(2);
    evidence[0].classId = {'r', 'o', 't'};
    evidence[0].measurementKey = 7;
    evidence[0].digest.fill(0x11);
    evidence[1].classId = {'b', 'm', 'c'};
    evidence[1].measurementKey = 9;
    evidence[1].digest.fill(0x22);

    auto claims = buildCompositeClaims(std::span<const std::uint8_t, 32>{nonce},
                                       ueid, kCompositeEatDraftProfileUri, {},
                                       evidence, std::nullopt);
    auto measurements = cbortest::decode(claims)->atInt(kMeasurements);
    ASSERT_TRUE(measurements && measurements->isArray());
    ASSERT_EQ(measurements->array.size(), evidence.size());

    for (std::size_t index = 0; index < evidence.size(); ++index)
    {
        auto entry = measurements->array[index];
        ASSERT_TRUE(entry->isArray());
        ASSERT_EQ(entry->array.size(), 2u);
        EXPECT_EQ(entry->array[0]->uarg, kTcgConciseEvidenceContentFormat);
        auto document = cbortest::decode(entry->array[1]->bytes);
        auto triples = document->atInt(0)->atInt(0);
        auto measurement = triples->array[0]->array[1]->array[0];
        EXPECT_EQ(measurement->atInt(0)->uarg, evidence[index].measurementKey);
        auto digest = measurement->atInt(1)->atInt(2)->array[0];
        EXPECT_EQ(digest->array[0]->text, "sha-384");
        EXPECT_EQ(digest->array[1]->bytes,
                  (std::vector<std::uint8_t>{evidence[index].digest.begin(),
                                             evidence[index].digest.end()}));
    }
}

TEST(EatBuilder, ConciseEvidenceRequiresClassId)
{
    auto nonce = nonceFill(0xAB);
    std::vector<std::uint8_t> ueid{0x01};
    std::vector<LeadAttesterConciseEvidence> meas(1);

    EXPECT_THROW(buildCompositeClaims(std::span<const std::uint8_t, 32>{nonce},
                                      ueid, kCompositeEatDraftProfileUri, {},
                                      meas, std::nullopt),
                 std::invalid_argument);
}

TEST(EatBuilder, MeasurementsAreRequired)
{
    auto nonce = nonceFill(0xAB);
    std::vector<std::uint8_t> ueid{0x01};

    EXPECT_THROW(buildCompositeClaims(std::span<const std::uint8_t, 32>{nonce},
                                      ueid, kCompositeEatDraftProfileUri, {},
                                      {}, std::nullopt),
                 std::invalid_argument);
}

TEST(EatBuilder, OptionalCorimLocator)
{
    std::vector<SubmoduleRecord> recs{recordFor("env.gpu.0", 0x11)};
    auto claims = buildSample(true, recs);
    auto root = cbortest::decode(claims);
    auto corim = root->atInt(kCorimId);
    ASSERT_TRUE(corim && corim->isText());
    EXPECT_EQ(corim->text, "tag:example.com,2026:platform-corim:v7");
}

TEST(EatBuilder, ProtectedHeader)
{
    auto hdr = buildProtectedHeader();
    auto root = cbortest::decode(hdr);
    ASSERT_TRUE(root->isMap());
    auto alg = root->atInt(1);
    ASSERT_TRUE(alg && alg->isInt());
    EXPECT_EQ(alg->ival, kAlgEs384);
    auto ct = root->atInt(3);
    ASSERT_TRUE(ct && ct->isText());
    EXPECT_EQ(ct->text, "application/eat+cwt");
}

TEST(EatBuilder, SigStructureShape)
{
    std::vector<std::uint8_t> prot{0x01};
    std::vector<std::uint8_t> payload{0x02, 0x03};
    auto sig = buildSigStructure(prot, payload);
    auto root = cbortest::decode(sig);
    ASSERT_TRUE(root->isArray());
    ASSERT_EQ(root->array.size(), 4u);
    EXPECT_EQ(root->array[0]->text, "Signature1");
    EXPECT_EQ(root->array[1]->bytes, prot);
    EXPECT_TRUE(root->array[2]->isBytes());
    EXPECT_EQ(root->array[2]->bytes.size(), 0u); // empty external_aad
    EXPECT_EQ(root->array[3]->bytes, payload);
}

TEST(EatBuilder, CwtCoseSign1Tags)
{
    std::vector<std::uint8_t> prot{0x01};
    std::vector<std::vector<std::uint8_t>> chain{{0xAA, 0xBB}};
    std::vector<std::uint8_t> payload{0x02};
    std::vector<std::uint8_t> sig(96, 0x05);

    auto token = assembleCwtCoseSign1(prot, chain, payload, sig);
    auto cwt = cbortest::decode(token);
    ASSERT_TRUE(cwt->isTag());
    EXPECT_EQ(cwt->tag, 61u); // CWT
    auto cose = cwt->tagged;
    ASSERT_TRUE(cose->isTag());
    EXPECT_EQ(cose->tag, 18u); // COSE_Sign1
    auto arr = cose->tagged;
    ASSERT_TRUE(arr->isArray());
    ASSERT_EQ(arr->array.size(), 4u);

    // unprotected header carries x5chain (33).
    auto unprot = arr->array[1];
    ASSERT_TRUE(unprot->isMap());
    auto x5 = unprot->atInt(33);
    ASSERT_TRUE(x5 && x5->isArray());
    ASSERT_EQ(x5->array.size(), 1u);
    EXPECT_EQ(x5->array[0]->bytes, (std::vector<std::uint8_t>{0xAA, 0xBB}));
}

} // namespace
} // namespace spdmd::mock_attester::eat
