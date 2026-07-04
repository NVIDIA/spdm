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

#include "mock_attester.hpp"

#include "eat_builder.hpp"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace spdmd::mock_attester
{

namespace
{

/// Convert a DER-encoded ECDSA signature into 96-byte fixed-width P1363
/// form (r||s, each 48 bytes, big-endian, zero-padded).
bool derEcdsaToP1363(const std::uint8_t* der, std::size_t derLen,
                     std::array<std::uint8_t, 96>& out)
{
    out.fill(0);
    if (derLen < 8 || der[0] != 0x30)
    {
        return false;
    }

    std::size_t pos = 2;
    if ((der[1] & 0x80U) != 0U)
    {
        pos = 2 + (der[1] & 0x7FU);
    }

    if (pos >= derLen || der[pos] != 0x02)
    {
        return false;
    }
    ++pos;
    std::size_t rLen = der[pos++];
    if (pos + rLen > derLen)
    {
        return false;
    }
    const std::uint8_t* rData = der + pos;
    pos += rLen;

    if (pos >= derLen || der[pos] != 0x02)
    {
        return false;
    }
    ++pos;
    std::size_t sLen = der[pos++];
    if (pos + sLen > derLen)
    {
        return false;
    }
    const std::uint8_t* sData = der + pos;

    while (rLen > 48 && rData[0] == 0x00)
    {
        ++rData;
        --rLen;
    }
    while (sLen > 48 && sData[0] == 0x00)
    {
        ++sData;
        --sLen;
    }
    if (rLen > 48 || sLen > 48)
    {
        return false;
    }

    std::memcpy(out.data() + (48 - rLen), rData, rLen);
    std::memcpy(out.data() + 48 + (48 - sLen), sData, sLen);
    return true;
}

std::string yyyymmddhhmmssUtc(std::time_t t)
{
    std::tm tmv{};
    gmtime_r(&t, &tmv);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d%02d",
                  tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour,
                  tmv.tm_min, tmv.tm_sec);
    return std::string{buf};
}

} // namespace

struct MockAttester::Impl
{
    MockAttesterConfig cfg;
    bool ready = false;
    std::string certChainPem;

    // Mock Lead Attester identity material.
    std::array<std::uint8_t, 16> ueid{};
    // Mock RoT/BMC measurement value (a fixed digest standing in for
    // platform firmware measurements).
    std::array<std::uint8_t, 48> bmcMeasurement{};

    mbedtls_entropy_context entropy{};
    mbedtls_ctr_drbg_context ctrDrbg{};
    mbedtls_pk_context pk{};

    explicit Impl(MockAttesterConfig c) : cfg(std::move(c))
    {
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctrDrbg);
        mbedtls_pk_init(&pk);
    }

    ~Impl()
    {
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctrDrbg);
        mbedtls_entropy_free(&entropy);
    }

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = delete;
    Impl& operator=(Impl&&) = delete;

    bool init()
    {
        static constexpr const char* pers = "spdmd_mock_attester";
        int rc = mbedtls_ctr_drbg_seed(
            &ctrDrbg, mbedtls_entropy_func, &entropy,
            reinterpret_cast<const unsigned char*>(pers), std::strlen(pers));
        if (rc != 0)
        {
            std::cerr << "MockAttester: ctr_drbg_seed failed: " << rc << '\n';
            return false;
        }

        // Stable-per-instance mock identity material.
        if (mbedtls_ctr_drbg_random(&ctrDrbg, ueid.data(), ueid.size()) != 0)
        {
            return false;
        }
        // Derive a deterministic mock BMC measurement from a fixed label.
        static constexpr const char* label = "mock-bmc-fw-measurement";
        if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA384),
                       reinterpret_cast<const unsigned char*>(label),
                       std::strlen(label), bmcMeasurement.data()) != 0)
        {
            return false;
        }

        rc = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
        if (rc != 0)
        {
            std::cerr << "MockAttester: pk_setup failed: " << rc << '\n';
            return false;
        }

        rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP384R1, mbedtls_pk_ec(pk),
                                 mbedtls_ctr_drbg_random, &ctrDrbg);
        if (rc != 0)
        {
            std::cerr << "MockAttester: ecp_gen_key failed: " << rc << '\n';
            return false;
        }

        if (!makeSelfSignedLeaf())
        {
            return false;
        }

        ready = true;
        return true;
    }

    bool makeSelfSignedLeaf()
    {
        mbedtls_x509write_cert crt;
        mbedtls_x509write_crt_init(&crt);

        mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
        mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA384);
        mbedtls_x509write_crt_set_subject_key(&crt, &pk);
        mbedtls_x509write_crt_set_issuer_key(&crt, &pk);

        std::string dn = "CN=" + cfg.leafCn + ",O=spdmd,OU=mock-attester";
        int rc = mbedtls_x509write_crt_set_subject_name(&crt, dn.c_str());
        if (rc != 0)
        {
            mbedtls_x509write_crt_free(&crt);
            return false;
        }
        rc = mbedtls_x509write_crt_set_issuer_name(&crt, dn.c_str());
        if (rc != 0)
        {
            mbedtls_x509write_crt_free(&crt);
            return false;
        }

        const unsigned char serialBytes[] = {0x01};
        mbedtls_x509write_crt_set_serial_raw(
            &crt, const_cast<unsigned char*>(serialBytes), sizeof(serialBytes));

        std::time_t now = std::time(nullptr);
        std::string notBefore = yyyymmddhhmmssUtc(now);
        std::string notAfter = yyyymmddhhmmssUtc(now + 10 * 365 * 24 * 3600);
        rc = mbedtls_x509write_crt_set_validity(&crt, notBefore.c_str(),
                                                notAfter.c_str());
        if (rc != 0)
        {
            mbedtls_x509write_crt_free(&crt);
            return false;
        }

        rc = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
        if (rc != 0)
        {
            mbedtls_x509write_crt_free(&crt);
            return false;
        }

        std::array<unsigned char, 4096> buf{};
        rc = mbedtls_x509write_crt_pem(&crt, buf.data(), buf.size(),
                                       mbedtls_ctr_drbg_random, &ctrDrbg);
        mbedtls_x509write_crt_free(&crt);
        if (rc != 0)
        {
            std::cerr << "MockAttester: write_crt_pem failed: " << rc << '\n';
            return false;
        }

        certChainPem = reinterpret_cast<const char*>(buf.data());
        return true;
    }

    composite::CompositeEatResponse
        generateCompositeEat(const composite::CompositeEatRequest& req)
    {
        composite::CompositeEatResponse result;
        if (!ready)
        {
            result.errorMsg = "MockAttester not initialized";
            return result;
        }

        // RoT-authored measurements (claim 273). One mock entry standing
        // in for platform RoT/BMC firmware measurements.
        std::vector<composite::LeadAttesterMeasurement> measurements;
        {
            composite::LeadAttesterMeasurement m;
            m.contentFormat = 0;
            m.value.assign(bmcMeasurement.begin(), bmcMeasurement.end());
            measurements.push_back(std::move(m));
        }

        // 1. Build composite EAT claims and the COSE protected header.
        std::vector<std::uint8_t> claims;
        std::vector<std::uint8_t> protectedHdr;
        try
        {
            claims = eat::buildCompositeClaims(
                std::span<const std::uint8_t, composite::kNonceLen>{req.nonce},
                ueid, cfg.profileUri, req.deviceRecords, measurements,
                req.platformCorimLocator);
            protectedHdr = eat::buildProtectedHeader();
        }
        catch (const std::exception& ex)
        {
            result.errorMsg = std::string{"eat_builder failed: "} + ex.what();
            return result;
        }

        // 2. Build COSE Sig_Structure and SHA-384 it for ECDSA.
        std::vector<std::uint8_t> sigStruct =
            eat::buildSigStructure(protectedHdr, claims);

        std::array<std::uint8_t, 48> hash{};
        if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA384),
                       sigStruct.data(), sigStruct.size(), hash.data()) != 0)
        {
            result.errorMsg = "SHA-384 failed";
            return result;
        }

        // 3. Sign with mbedtls (DER output).
        std::array<unsigned char, 200> derBuf{};
        std::size_t derLen = 0;
        int rc = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA384, hash.data(),
                                 hash.size(), derBuf.data(), derBuf.size(),
                                 &derLen, mbedtls_ctr_drbg_random, &ctrDrbg);
        if (rc != 0)
        {
            char errbuf[128];
            mbedtls_strerror(rc, errbuf, sizeof(errbuf));
            result.errorMsg = std::string{"mbedtls_pk_sign failed: "} + errbuf;
            return result;
        }

        // 4. DER -> P1363 (96-byte r||s).
        std::array<std::uint8_t, 96> sigP1363{};
        if (!derEcdsaToP1363(derBuf.data(), derLen, sigP1363))
        {
            result.errorMsg = "DER -> P1363 conversion failed";
            return result;
        }

        // 5. Assemble final CWT(COSE_Sign1) token.
        auto chainDer = eat::pemToDerChain(certChainPem);
        try
        {
            result.compositeEat = eat::assembleCwtCoseSign1(
                protectedHdr, std::span{chainDer}, claims, std::span{sigP1363});
        }
        catch (const std::exception& ex)
        {
            result.errorMsg = std::string{"COSE assembly failed: "} + ex.what();
            return result;
        }

        result.success = true;
        return result;
    }
};

MockAttester::MockAttester(MockAttesterConfig cfg) :
    impl(std::make_unique<Impl>(std::move(cfg)))
{
    if (!impl->init())
    {
        std::cerr << "MockAttester: initialization failed\n";
    }
}

MockAttester::~MockAttester() = default;
MockAttester::MockAttester(MockAttester&&) noexcept = default;
MockAttester& MockAttester::operator=(MockAttester&&) noexcept = default;

composite::CompositeEatResponse MockAttester::generateCompositeEat(
    const composite::CompositeEatRequest& req)
{
    if (!impl)
    {
        composite::CompositeEatResponse r;
        r.errorMsg = "MockAttester moved-from";
        return r;
    }
    return impl->generateCompositeEat(req);
}

PlatformAttesterStatus MockAttester::getStatus() const
{
    if (impl && impl->ready)
    {
        return PlatformAttesterStatus::SoftwareMock;
    }
    return PlatformAttesterStatus::Unavailable;
}

const std::string& MockAttester::getCertChainPEM() const
{
    static const std::string empty;
    return impl ? impl->certChainPem : empty;
}

std::span<const std::uint8_t> MockAttester::getUeid() const
{
    if (!impl)
    {
        return {};
    }
    return std::span<const std::uint8_t>{impl->ueid.data(), impl->ueid.size()};
}

} // namespace spdmd::mock_attester
