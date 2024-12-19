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

#pragma once

#include "assert.hpp"
#include "flag.hpp"
#include "log.hpp"

#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <vector>

#define MBEDTLS_X509_MAX_DN_NAME_SIZE 256

namespace spdmcpp
{

inline void mbedtlsPrintErrorString(LogClass& log, int error)
{
    std::array<char, 128> str{};
    mbedtls_strerror(error, str.data(), str.size());
    log.print(str.data());
}

inline void mbedtlsPrintErrorLine(LogClass& log, const char* prefix, int error)
{
    std::array<char, 128> str{};
    mbedtls_strerror(error, str.data(), str.size());
    log.iprint(prefix);
    log.print(" = ");
    log.print(error);
    log.print(" = '");
    log.print(str.data());
    log.println('\'');
}

inline std::string mbedtlsToInfoString(mbedtls_x509_crt* c)
{
    std::string info;
    info.resize(4096);

    int ret = mbedtls_x509_crt_info(info.data(), info.size(), "", c);
    if (ret < 0)
    {
        return std::string("mbedtls_x509_crt_info returned error=") +
               std::to_string(ret);
    }
    if (static_cast<size_t>(ret) > info.size())
    {
        info.resize(ret + 1); //+1 for the null byte which mbedtls_x509_crt_info
                              // will want to write
        ret = mbedtls_x509_crt_info(info.data(), info.size(), "", c);
        if (ret < 0)
        {
            return std::string("mbedtls_x509_crt_info returned error=") +
                   std::to_string(ret);
        }
    }
    info.resize(ret);
    return info;
}

inline mbedtls_ecp_group_id toMbedtlsGroupID(SignatureEnum algo)
{
    // TODO decide which groups should be used and/or if it should be
    // configurable etc
    switch (algo)
    {
        case SignatureEnum::TPM_ALG_ECDSA_ECC_NIST_P256:
            return MBEDTLS_ECP_DP_SECP256R1;
        case SignatureEnum::TPM_ALG_ECDSA_ECC_NIST_P384:
            return MBEDTLS_ECP_DP_SECP384R1;
        case SignatureEnum::TPM_ALG_ECDSA_ECC_NIST_P521:
            return MBEDTLS_ECP_DP_BP512R1;
        default:
            return MBEDTLS_ECP_DP_NONE;
    }
}

// TODO figure out something better... or switch to openssl (preferred)
inline size_t getHalfSize(mbedtls_ecp_group_id id)
{
    switch (id)
    {
        case MBEDTLS_ECP_DP_SECP256R1:
        case MBEDTLS_ECP_DP_SECP256K1:
        case MBEDTLS_ECP_DP_BP256R1:
            return 32;
            break;
        case MBEDTLS_ECP_DP_SECP384R1:
        case MBEDTLS_ECP_DP_BP384R1:
            return 48;
            break;
        case MBEDTLS_ECP_DP_SECP521R1:
        case MBEDTLS_ECP_DP_BP512R1:
            return 66;
            break;
        default:
            SPDMCPP_ASSERT(false);
            return 0;
    }
}
inline size_t getHalfSize(const mbedtls_ecp_group& grp)
{
    return getHalfSize(grp.id);
}
inline size_t getHalfSize(const mbedtls_ecp_keypair& ctx)
{
    return getHalfSize(ctx.private_grp);
}

inline size_t getHalfSize(const mbedtls_ecdh_context& ctx)
{
    return getHalfSize(ctx.private_grp_id);
}

template <class T, auto INIT, auto FREE>
struct MbedtlsStructWrapper
{
    T obj;

    MbedtlsStructWrapper()
    {
        INIT(&obj);
    }
    ~MbedtlsStructWrapper()
    {
        FREE(&obj);
    }

    MbedtlsStructWrapper(const MbedtlsStructWrapper& other) = delete;
    MbedtlsStructWrapper& operator=(const MbedtlsStructWrapper&) = delete;

    MbedtlsStructWrapper(MbedtlsStructWrapper&&) = delete;
    MbedtlsStructWrapper& operator=(MbedtlsStructWrapper&&) = delete;

    T* get()
    {
        return &obj;
    }

    operator T&()
    {
        return obj;
    }
    operator T*()
    {
        return &obj;
    }
    T* operator->()
    {
        return &obj;
    }
};

using mbedtls_mpi_raii =
    MbedtlsStructWrapper<mbedtls_mpi, mbedtls_mpi_init, mbedtls_mpi_free>;
using mbedtls_x509_crt_raii =
    MbedtlsStructWrapper<mbedtls_x509_crt, mbedtls_x509_crt_init,
                         mbedtls_x509_crt_free>;
using mbedtls_ecdh_context_raii =
    MbedtlsStructWrapper<mbedtls_ecdh_context, mbedtls_ecdh_init,
                         mbedtls_ecdh_free>;

inline int verifySignature(mbedtls_x509_crt* cert,
                           const std::vector<uint8_t>& signature,
                           const std::vector<uint8_t>& hash)
{
    if (!cert)
    {
        errno = -EINVAL;
        return -1;
    }
#if 0

		// mbedtls_pk_context argh;
		// mbedtls_pk_init(&argh);
		// mbedtls_pk_setup(&argh, cert->pk.pk_info);
		int ret = mbedtls_pk_verify(&cert->pk, MBEDTLS_MD_NONE, hash.data(), hash.size(), signature.data(), signature.size());
	/*	SPDMCPP_LOG_TRACE_RS(Log, ret);
		if (ret) {
			Log.iprint("mbedtls_pk_verify ret = ");
			Log.print(ret);
			Log.print(" = '");
			Log.print(mbedtls_high_level_strerr(ret));
			Log.println('\'');
		}*/
    return ret;
#else
    if (mbedtls_pk_get_type(&cert->pk) != MBEDTLS_PK_ECKEY)
    {
        SPDMCPP_ASSERT(false);
    }
    int ret;
    mbedtls_ecp_keypair* ec_key = mbedtls_pk_ec(cert->pk);
    if (ec_key == nullptr)
    {
        return MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }

    size_t halfSize = getHalfSize(ec_key->private_grp);
    if (signature.size() != halfSize * 2)
    {
        return -1;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-init-variables)
    mbedtls_mpi_raii bnR{};
    // NOLINTNEXTLINE(cppcoreguidelines-init-variables)
    mbedtls_mpi_raii bnS{};

    ret = mbedtls_mpi_read_binary(bnR, signature.data(), halfSize);
    if (ret != 0)
    {
        return ret;
    }
    ret = mbedtls_mpi_read_binary(bnS, &signature[halfSize], halfSize);
    if (ret != 0)
    {
        return ret;
    }

    ret = mbedtls_ecdsa_verify(&ec_key->private_grp, hash.data(), hash.size(),
                               &ec_key->private_Q, bnR.get(), bnS.get());

    return ret;
#endif
}

/** @brief This function interprets the response previously stored in
 * ResponseBuffer
 *  @param[in] buf - Buffer with data to parse
 *  @param[inout] off - Offset to start at, will be adjusted as parsing goes on
 * and will point after the last parsed byte
 *  @returns pair containing return code from mbedtls_x509_crt_parse_der (0 on
 * success or "a specific X509 or PEM error code") and pointer to the created
 * mbedtls_x509_crt or nullptr on error
 */

inline std::pair<int, std::unique_ptr<mbedtls_x509_crt_raii>>
    mbedtlsCertParseDer(const std::vector<uint8_t>& buf, size_t& off)
{
    auto cert = std::make_unique<mbedtls_x509_crt_raii>();

    int ret = mbedtls_x509_crt_parse_der(*cert, &buf[off], buf.size() - off);
    if (ret)
    {
        return std::make_pair(ret, nullptr);
    }

    size_t asn1Len = 0;
    { // clang-format off
        const uint8_t* s = &buf[off];
        uint8_t* p = const_cast<uint8_t*>(s); // NOLINT cppcoreguidelines-pro-type-const-cast
        ret = mbedtls_asn1_get_tag(&p,
            buf.data() + buf.size(), //NOLINT cppcoreguidelines-pro-bounds-pointer-arithmetic
            &asn1Len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        SPDMCPP_ASSERT(ret == 0);
        asn1Len += (p - s);
    } // clang-format on
    off += asn1Len;
    return std::make_pair(ret, std::move(cert));
}

/** @brief Converts mbedtls_x509_time struct to Unix timestamp in milliseconds
 *  @param[in] t - mbedtls_x509_time struct containing date/time information
 *  @returns Unix timestamp in milliseconds (milliseconds since epoch)
 *
 *  This function takes an mbedtls_x509_time struct which contains calendar
 * date/time fields and converts it to a Unix timestamp (milliseconds since
 * epoch). The conversion accounts for the different field representations
 * between mbedtls_x509_time and std::tm structs.
 */
inline uint64_t convertMbedtlsTime(const mbedtls_x509_time& t)
{
    std::tm tmVal{};
    // In mbedtls_x509_time, year is stored as full year (e.g., 2024)
    // In std::tm, year is stored as years since 1900 (e.g., 124 for 2024)
    tmVal.tm_year = t.year - 1900;

    // In mbedtls_x509_time, month is 1-12 (January = 1)
    // In std::tm, month is 0-11 (January = 0)
    tmVal.tm_mon = t.mon - 1;
    tmVal.tm_mday = t.day;
    tmVal.tm_hour = t.hour;
    tmVal.tm_min = t.min;
    tmVal.tm_sec = t.sec;
    time_t timeSinceEpoch = timegm(&tmVal);
    return static_cast<uint64_t>(timeSinceEpoch) * 1000ULL;
}

/** @brief Gets the key usage flags from an X.509 certificate
 *  @param[in] cert - Pointer to mbedtls_x509_crt certificate structure
 *  @returns Vector of strings representing the key usage flags that are set
 *
 *  This function examines the key usage extension flags in the X.509
 * certificate and returns a vector of human-readable strings for each usage
 * that is enabled. The possible key usages are:
 *  - DigitalSignature: For digital signatures
 *  - NonRepudiation: For non-repudiation
 *  - KeyEncipherment: For key encryption
 *  - DataEncipherment: For data encryption
 *  - KeyCertSign: For signing certificates
 *  - CRLSigning: For signing CRLs
 *  - EncipherOnly: For encryption only
 *  - DecipherOnly: For decryption only
 */
inline std::vector<std::string> getKeyUsage(LogClass& log,
                                            const mbedtls_x509_crt* cert)
{
    if (cert == nullptr)
    {
        log.iprint("getKeyUsage: Certificate pointer is null");
        log.println('\'');
        return {};
    }

    static const std::array<std::pair<unsigned int, std::string_view>, 8>
        keyUsageMap = {{{MBEDTLS_X509_KU_DIGITAL_SIGNATURE, "DigitalSignature"},
                        {MBEDTLS_X509_KU_NON_REPUDIATION, "NonRepudiation"},
                        {MBEDTLS_X509_KU_KEY_ENCIPHERMENT, "KeyEncipherment"},
                        {MBEDTLS_X509_KU_DATA_ENCIPHERMENT, "DataEncipherment"},
                        {MBEDTLS_X509_KU_KEY_CERT_SIGN, "KeyCertSign"},
                        {MBEDTLS_X509_KU_CRL_SIGN, "CRLSigning"},
                        {MBEDTLS_X509_KU_ENCIPHER_ONLY, "EncipherOnly"},
                        {MBEDTLS_X509_KU_DECIPHER_ONLY, "DecipherOnly"}}};

    std::vector<std::string> usage;
    usage.reserve(keyUsageMap.size());

    for (const auto& [flag, name] : keyUsageMap)
    {
        if ((cert->key_usage & flag) != 0)
        {
            usage.push_back(std::string(name));
        }
    }

    return usage;
}

/** @brief Structure to hold parsed certificate information */
struct CertificateInfo
{
    std::string certificate; // The PEM certificate string
    std::string issuer;
    std::string subject;
    uint64_t notBefore{0};
    uint64_t notAfter{0};
    std::vector<std::string> keyUsage;
};

/** @brief Parses a PEM-formatted X.509 certificate
 *  @param[in] log - Logger for errors
 *  @param[in] certPEM - PEM certificate to parse
 *  @return CertificateInfo containing parsed certificate data
 *  @throws std::invalid_argument if certificate data is invalid
 *  @throws std::runtime_error if certificate parsing fails
 */
inline CertificateInfo parseCertificatePEM(LogClass& log,
                                           const std::string& certPEM)
{
    CertificateInfo info;

    if (certPEM.empty())
    {
        throw std::invalid_argument("Empty certificate provided");
    }

    mbedtls_x509_crt_raii chain;

    int rc = mbedtls_x509_crt_parse(
        chain, reinterpret_cast<const unsigned char*>(certPEM.data()),
        certPEM.size() + 1);
    if (rc < 0)
    {
        std::string msg = "Failed to parse certificate chain: ";
        mbedtlsPrintErrorString(log, rc);
        throw std::runtime_error(msg);
    }

    constexpr size_t maxDNLen = MBEDTLS_X509_MAX_DN_NAME_SIZE;
    std::vector<char> dnBuf(maxDNLen + 1); // +1 for null terminator

    // Use the first certificate in the chain as it is the leaf certificate
    int ret = mbedtls_x509_dn_gets(dnBuf.data(), dnBuf.size(), &chain->issuer);
    if (ret < 0)
    {
        std::string msg = "Failed to get issuer DN: ";
        mbedtlsPrintErrorString(log, ret);
        throw std::runtime_error(msg);
    }
    std::string issuer = dnBuf.data();
    if (issuer.empty())
    {
        throw std::invalid_argument("Missing issuer DN");
    }

    ret = mbedtls_x509_dn_gets(dnBuf.data(), dnBuf.size(), &chain->subject);
    if (ret < 0)
    {
        std::string msg = "Failed to get subject DN: ";
        mbedtlsPrintErrorString(log, ret);
        throw std::runtime_error(msg);
    }
    std::string subject = dnBuf.data();
    if (subject.empty())
    {
        throw std::invalid_argument("Missing subject DN");
    }

    uint64_t notBefore = convertMbedtlsTime(chain->valid_from);
    uint64_t notAfter = convertMbedtlsTime(chain->valid_to);
    if (notBefore == 0 || notAfter == 0)
    {
        throw std::invalid_argument("Invalid validity period");
    }

    auto keyUsage = getKeyUsage(log, chain);
    if (keyUsage.empty())
    {
        throw std::invalid_argument("No key usage found");
    }

    info.certificate = certPEM;
    info.issuer = std::move(issuer);
    info.subject = std::move(subject);
    info.notBefore = notBefore;
    info.notAfter = notAfter;
    info.keyUsage = std::move(keyUsage);

    return info;
}

} // namespace spdmcpp
