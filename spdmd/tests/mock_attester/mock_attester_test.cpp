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

// Unit tests for MockAttester — full generateCompositeEat() round-trip:
// decodes the CWT(COSE_Sign1) token, extracts the embedded x5chain,
// parses the leaf cert with mbedtls, verifies the ES384 signature over
// the COSE Sig_Structure, and checks the nonce / ueid / submods claims.

#include "../composite/cbor_test_util.hpp"
#include "mock_attester/eat_builder.hpp"
#include "mock_attester/mock_attester.hpp"

#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>

#include <array>
#include <cstring>
#include <span>
#include <vector>

#include <gtest/gtest.h>

namespace spdmd::mock_attester
{
namespace
{

using composite::CompositeEatRequest;
using composite::SubmoduleRecord;

SubmoduleRecord recordFor(const std::string& env, std::uint8_t fill)
{
    SubmoduleRecord r;
    r.environmentId = env;
    r.hashAlgId = composite::kCoseAlgSha384;
    r.digest.fill(fill);
    return r;
}

CompositeEatRequest sampleRequest()
{
    CompositeEatRequest req;
    req.nonce.fill(0x5A);
    req.deviceRecords.push_back(recordFor("env.gpu.0", 0x11));
    req.deviceRecords.push_back(recordFor("env.nic.0", 0x22));
    return req;
}

// Verify ES384 over the COSE Sig_Structure with the leaf cert pubkey.
bool verifyCose(const std::vector<std::uint8_t>& leafDer,
                const std::vector<std::uint8_t>& protectedHdr,
                const std::vector<std::uint8_t>& payload,
                const std::vector<std::uint8_t>& sig96)
{
    if (sig96.size() != 96)
    {
        return false;
    }
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse_der(&crt, leafDer.data(), leafDer.size()) != 0)
    {
        mbedtls_x509_crt_free(&crt);
        return false;
    }

    auto sigStruct = eat::buildSigStructure(protectedHdr, payload);
    std::array<std::uint8_t, 48> hash{};
    bool ok = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA384),
                         sigStruct.data(), sigStruct.size(), hash.data()) == 0;

    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    ok = ok && mbedtls_mpi_read_binary(&r, sig96.data(), 48) == 0;
    ok = ok && mbedtls_mpi_read_binary(&s, sig96.data() + 48, 48) == 0;

    if (ok)
    {
        mbedtls_ecp_keypair* kp = mbedtls_pk_ec(crt.pk);
        ok = mbedtls_ecdsa_verify(&kp->MBEDTLS_PRIVATE(grp), hash.data(),
                                  hash.size(), &kp->MBEDTLS_PRIVATE(Q), &r,
                                  &s) == 0;
    }

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_x509_crt_free(&crt);
    return ok;
}

TEST(MockAttester, ReadyAndStatus)
{
    MockAttester att;
    EXPECT_EQ(att.getStatus(), PlatformAttesterStatus::SoftwareMock);
    EXPECT_FALSE(att.getCertChainPEM().empty());
    EXPECT_EQ(att.getUeid().size(), 16u);
}

TEST(MockAttester, AttestCompositeSucceeds)
{
    MockAttester att;
    auto res = att.generateCompositeEat(sampleRequest());
    ASSERT_TRUE(res.success) << res.errorMsg;
    EXPECT_FALSE(res.compositeEat.empty());
}

TEST(MockAttester, TokenSignatureVerifies)
{
    MockAttester att;
    auto res = att.generateCompositeEat(sampleRequest());
    ASSERT_TRUE(res.success) << res.errorMsg;

    // Unwrap CWT(61) -> COSE_Sign1(18) -> [protected, unprot, payload, sig].
    auto cwt = cbortest::decode(res.compositeEat);
    ASSERT_TRUE(cwt->isTag());
    ASSERT_EQ(cwt->tag, 61u);
    auto cose = cwt->tagged;
    ASSERT_TRUE(cose->isTag());
    ASSERT_EQ(cose->tag, 18u);
    auto arr = cose->tagged;
    ASSERT_TRUE(arr->isArray());
    ASSERT_EQ(arr->array.size(), 4u);

    const auto& protectedHdr = arr->array[0]->bytes;
    const auto& payload = arr->array[2]->bytes;
    const auto& sig = arr->array[3]->bytes;

    auto x5 = arr->array[1]->atInt(33);
    ASSERT_TRUE(x5 && x5->isArray());
    ASSERT_GE(x5->array.size(), 1u);
    const auto& leafDer = x5->array[0]->bytes;

    EXPECT_TRUE(verifyCose(leafDer, protectedHdr, payload, sig));
}

TEST(MockAttester, ClaimsCarryNonceUeidAndSubmods)
{
    MockAttester att;
    auto req = sampleRequest();
    auto res = att.generateCompositeEat(req);
    ASSERT_TRUE(res.success) << res.errorMsg;

    auto cwt = cbortest::decode(res.compositeEat);
    auto payload = cwt->tagged->tagged->array[2]->bytes;
    auto claims = cbortest::decode(payload);

    // nonce (10) echoes the request nonce.
    auto nonce = claims->atInt(10);
    ASSERT_TRUE(nonce && nonce->isBytes());
    EXPECT_EQ(nonce->bytes,
              std::vector<std::uint8_t>(req.nonce.begin(), req.nonce.end()));

    // ueid (256) equals the attester's identity.
    auto ueid = claims->atInt(256);
    ASSERT_TRUE(ueid && ueid->isBytes());
    auto attUeid = att.getUeid();
    EXPECT_EQ(ueid->bytes,
              std::vector<std::uint8_t>(attUeid.begin(), attUeid.end()));

    // submods (266) carries both env keys.
    auto submods = claims->atInt(266);
    ASSERT_TRUE(submods && submods->isMap());
    EXPECT_TRUE(submods->atText("env.gpu.0"));
    EXPECT_TRUE(submods->atText("env.nic.0"));

    // measurements (273) present.
    ASSERT_TRUE(claims->atInt(273));
}

TEST(MockAttester, CorimLocatorPlumbedThrough)
{
    MockAttester att;
    auto req = sampleRequest();
    req.platformCorimLocator = "tag:example.com,2026:platform-corim:v7";
    auto res = att.generateCompositeEat(req);
    ASSERT_TRUE(res.success) << res.errorMsg;

    auto cwt = cbortest::decode(res.compositeEat);
    auto payload = cwt->tagged->tagged->array[2]->bytes;
    auto claims = cbortest::decode(payload);
    auto corim = claims->atInt(-75000);
    ASSERT_TRUE(corim && corim->isText());
    EXPECT_EQ(corim->text, "tag:example.com,2026:platform-corim:v7");
}

} // namespace
} // namespace spdmd::mock_attester
