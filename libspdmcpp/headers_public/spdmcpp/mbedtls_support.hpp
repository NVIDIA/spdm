
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

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <vector>

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
        case SignatureEnum::ECDSA_ECC_NIST_P256:
            return MBEDTLS_ECP_DP_SECP256R1;
        case SignatureEnum::ECDSA_ECC_NIST_P384:
            return MBEDTLS_ECP_DP_SECP384R1;
        case SignatureEnum::ECDSA_ECC_NIST_P521:
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
inline size_t getHalfSize(const mbedtls_ecp_group* grp)
{
    return getHalfSize(grp->id);
}
inline size_t getHalfSize(const mbedtls_ecp_keypair* ctx)
{
    return getHalfSize(&ctx->grp);
}
inline size_t getHalfSize(const mbedtls_ecdh_context* ctx)
{
    return getHalfSize(&ctx->grp);
}

inline int verifySignature(mbedtls_x509_crt* cert,
                           const std::vector<uint8_t>& signature,
                           const std::vector<uint8_t>& hash)
{
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
    mbedtls_ecdh_context ctx;
    mbedtls_ecdh_init(&ctx);

    int ret = mbedtls_ecdh_get_params(&ctx, mbedtls_pk_ec(cert->pk),
                                      MBEDTLS_ECDH_OURS);
    if (ret != 0)
    {
        mbedtls_ecdh_free(&ctx);
        SPDMCPP_ASSERT(false);
        return ret;
    }

    size_t halfSize = getHalfSize(&ctx);
    if (signature.size() != halfSize * 2)
    {
        SPDMCPP_ASSERT(false);
        mbedtls_ecdh_free(&ctx);
        return -1;
    }

    mbedtls_mpi bnR, bnS;
    mbedtls_mpi_init(&bnR);
    mbedtls_mpi_init(&bnS);

    ret = mbedtls_mpi_read_binary(&bnR, signature.data(), halfSize);
    if (ret != 0)
    {
        mbedtls_mpi_free(&bnR);
        mbedtls_mpi_free(&bnS);
        SPDMCPP_ASSERT(false);
        mbedtls_ecdh_free(&ctx);
        return ret;
    }
    ret = mbedtls_mpi_read_binary(&bnS, &signature[halfSize], halfSize);
    if (ret != 0)
    {
        mbedtls_mpi_free(&bnR);
        mbedtls_mpi_free(&bnS);
        SPDMCPP_ASSERT(false);
        mbedtls_ecdh_free(&ctx);
        return ret;
    }
    ret = mbedtls_ecdsa_verify(&ctx.grp, hash.data(), hash.size(), &ctx.Q, &bnR,
                               &bnS);
    mbedtls_mpi_free(&bnR);
    mbedtls_mpi_free(&bnS);

    mbedtls_ecdh_free(&ctx);
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

inline std::pair<int, mbedtls_x509_crt*>
    mbedtlsCertParseDer(const std::vector<uint8_t>& buf, size_t& off)
{
    auto* cert = new mbedtls_x509_crt;
    mbedtls_x509_crt_init(cert);

    int ret = mbedtls_x509_crt_parse_der(cert, &buf[off], buf.size() - off);
    if (ret)
    {
        mbedtls_x509_crt_free(cert);
        delete cert;
        return std::make_pair(ret, nullptr);
    }

    size_t asn1Len = 0;
    {
        const uint8_t* s = &buf[off];
        uint8_t* p = const_cast<uint8_t*>(s); // NOLINT cppcoreguidelines-pro-type-const-cast
        ret = mbedtls_asn1_get_tag(&p,
            buf.data() + buf.size(), //NOLINT cppcoreguidelines-pro-bounds-pointer-arithmetic
            &asn1Len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        SPDMCPP_ASSERT(ret == 0);
        asn1Len += (p - s);
    }
    off += asn1Len;
    return std::make_pair(ret, cert);
}

} // namespace spdmcpp
