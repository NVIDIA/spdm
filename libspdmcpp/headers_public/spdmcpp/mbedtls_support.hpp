
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

} // namespace spdmcpp
