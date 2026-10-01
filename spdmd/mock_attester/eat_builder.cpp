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

#include "eat_builder.hpp"

#include "composite/cbor_det.hpp"

#include <mbedtls/base64.h>

#include <stdexcept>
#include <string>

namespace spdmd::mock_attester::eat
{

namespace cbor = ::spdmd::composite::cbor;

namespace
{

// COSE header labels (RFC 9052 §3).
constexpr std::int64_t kCoseHeaderAlg = 1;
constexpr std::int64_t kCoseHeaderContentType = 3;
constexpr std::int64_t kCoseHeaderX5chain = 33;

// EAT claim keys (RFC 9711 / RFC 8392).
constexpr std::int64_t kEatClaimNonce = 10;
constexpr std::int64_t kEatClaimUeid = 256;
constexpr std::int64_t kEatClaimProfile = 265;
constexpr std::int64_t kEatClaimSubmods = 266;
constexpr std::int64_t kEatClaimMeasurements = 273;

// TBD Platform CoRIM locator claim. Profile-defined, private-use key
// pending a registered allocation.
constexpr std::int64_t kEatClaimPlatformCorimId = -75000;

// CWT (RFC 8392) and COSE_Sign1 (RFC 9052) CBOR tags.
constexpr std::uint64_t kCborTagCwt = 61;
constexpr std::uint64_t kCborTagCoseSign1 = 18;

// Measurement entry keys.
constexpr const char* kMeasContentFormat = "content-format";
constexpr const char* kMeasValue = "value";

/// Encode one detached-submodule-digest: [hash-alg, digest].
std::vector<std::uint8_t>
    encodeSubmodDigest(const composite::SubmoduleRecord& r)
{
    std::vector<std::vector<std::uint8_t>> elems;
    elems.push_back(cbor::intVal(r.hashAlgId));
    elems.push_back(cbor::bytesVal(r.digest));
    return cbor::arrayVal(elems);
}

/// Encode one Lead Attester measurement: {"content-format", "value"}.
std::vector<std::uint8_t>
    encodeMeasurement(const composite::LeadAttesterMeasurement& m)
{
    if (!m.contentFormat)
    {
        throw std::invalid_argument(
            "Lead Attester measurement content-format is required");
    }
    cbor::Map em;
    em.addText(kMeasContentFormat, cbor::uintVal(*m.contentFormat));
    em.addText(kMeasValue, cbor::bytesVal(m.value));
    return em.encode();
}

} // namespace

std::vector<std::uint8_t> buildCompositeClaims(
    std::span<const std::uint8_t, composite::kNonceLen> nonce,
    std::span<const std::uint8_t> ueid, std::string_view profileUri,
    std::span<const composite::SubmoduleRecord> submods,
    std::span<const composite::LeadAttesterMeasurement> measurements,
    const std::optional<std::string>& platformCorimLocator)
{
    cbor::Map claims;

    // eat_nonce (10)
    claims.addInt(kEatClaimNonce, cbor::bytesVal(nonce));

    // ueid (256)
    claims.addInt(kEatClaimUeid, cbor::bytesVal(ueid));

    // eat_profile (265)
    claims.addInt(kEatClaimProfile, cbor::textVal(profileUri));

    // submods (266): map { env.* => [hash-alg, digest] }
    {
        cbor::Map submodMap;
        for (const auto& r : submods)
        {
            submodMap.addText(r.environmentId, encodeSubmodDigest(r));
        }
        claims.addInt(kEatClaimSubmods, submodMap.encode());
    }

    // measurements (273): [ {content-format, value}, ... ]
    {
        std::vector<std::vector<std::uint8_t>> arr;
        arr.reserve(measurements.size());
        for (const auto& m : measurements)
        {
            arr.push_back(encodeMeasurement(m));
        }
        claims.addInt(kEatClaimMeasurements, cbor::arrayVal(arr));
    }

    // Optional Platform CoRIM locator hint.
    if (platformCorimLocator)
    {
        claims.addInt(kEatClaimPlatformCorimId,
                      cbor::textVal(*platformCorimLocator));
    }

    return claims.encode();
}

std::vector<std::uint8_t> buildProtectedHeader(int alg)
{
    cbor::Map hdr;
    hdr.addInt(kCoseHeaderAlg, cbor::intVal(alg));
    hdr.addInt(kCoseHeaderContentType, cbor::textVal(kContentTypeEatCwt));
    return hdr.encode();
}

std::vector<std::uint8_t>
    buildSigStructure(std::span<const std::uint8_t> protectedHeader,
                      std::span<const std::uint8_t> payload)
{
    std::vector<std::vector<std::uint8_t>> elems;
    elems.push_back(cbor::textVal("Signature1"));
    elems.push_back(cbor::bytesVal(protectedHeader));
    elems.push_back(cbor::bytesVal(std::span<const std::uint8_t>{}));
    elems.push_back(cbor::bytesVal(payload));
    return cbor::arrayVal(elems);
}

std::vector<std::uint8_t>
    assembleCwtCoseSign1(std::span<const std::uint8_t> protectedHeader,
                         std::span<const std::vector<std::uint8_t>> x5chainDer,
                         std::span<const std::uint8_t> payload,
                         std::span<const std::uint8_t> signature)
{
    std::vector<std::uint8_t> out;

    // 61(18([ protected, unprotected, payload, signature ]))
    cbor::putTag(out, kCborTagCwt);
    cbor::putTag(out, kCborTagCoseSign1);
    cbor::putArrayHeader(out, 4);

    // [0] body_protected: bstr
    cbor::putBytes(out, protectedHeader);

    // [1] unprotected: map { 33: [cert_der, ...] } (empty map if no chain)
    cbor::Map unprot;
    if (!x5chainDer.empty())
    {
        std::vector<std::vector<std::uint8_t>> chain;
        chain.reserve(x5chainDer.size());
        for (const auto& der : x5chainDer)
        {
            chain.push_back(cbor::bytesVal(der));
        }
        unprot.addInt(kCoseHeaderX5chain, cbor::arrayVal(chain));
    }
    const std::vector<std::uint8_t> unprotBytes = unprot.encode();
    out.insert(out.end(), unprotBytes.begin(), unprotBytes.end());

    // [2] payload: bstr
    cbor::putBytes(out, payload);

    // [3] signature: bstr
    cbor::putBytes(out, signature);

    return out;
}

std::vector<std::vector<std::uint8_t>> pemToDerChain(std::string_view pem)
{
    static constexpr std::string_view kBegin = "-----BEGIN CERTIFICATE-----";
    static constexpr std::string_view kEnd = "-----END CERTIFICATE-----";

    std::vector<std::vector<std::uint8_t>> chain;
    std::size_t pos = 0;

    while (pos < pem.size())
    {
        std::size_t begin = pem.find(kBegin, pos);
        if (begin == std::string_view::npos)
        {
            break;
        }
        std::size_t end = pem.find(kEnd, begin);
        if (end == std::string_view::npos)
        {
            break;
        }

        std::string b64;
        b64.reserve(end - begin);
        for (std::size_t i = begin + kBegin.size(); i < end; ++i)
        {
            char c = pem[i];
            if (c != '\n' && c != '\r' && c != ' ' && c != '\t')
            {
                b64.push_back(c);
            }
        }

        std::size_t derLen = 0;
        mbedtls_base64_decode(
            nullptr, 0, &derLen,
            reinterpret_cast<const unsigned char*>(b64.data()), b64.size());
        if (derLen > 0)
        {
            std::vector<std::uint8_t> der(derLen);
            int rc = mbedtls_base64_decode(
                der.data(), der.size(), &derLen,
                reinterpret_cast<const unsigned char*>(b64.data()), b64.size());
            if (rc == 0)
            {
                der.resize(derLen);
                chain.push_back(std::move(der));
            }
        }

        pos = end + kEnd.size();
    }

    return chain;
}

} // namespace spdmd::mock_attester::eat
