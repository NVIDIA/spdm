
#pragma once

#include "flag.hpp"
#include "log.hpp"

#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/error.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <vector>

namespace spdmcpp
{

inline void mbedtlsPrintErrorString(LogClass& log, int error)
{
    std::array<char, 128> str;
    mbedtls_strerror(error, str.data(), str.size());
    log.print(str.data());
}
inline void mbedtlsPrintErrorLine(LogClass& log, const char* prefix, int error)
{
    std::array<char, 128> str;
    mbedtls_strerror(error, str.data(), str.size());
    log.iprint(prefix);
    log.print(" = ");
    log.print(error);
    log.print(" = '");
    log.print(str.data());
    log.println('\'');
}


inline int verifySignature(mbedtls_x509_crt* cert,
                           const std::vector<uint8_t>& signature,
                           const std::vector<uint8_t>& hash)
{
#if 0
		mbedtls_pk_context argh;
		mbedtls_pk_init(&argh);
		mbedtls_pk_setup(&argh, cert->pk.pk_info);
		ret = mbedtls_pk_verify(&cert->pk, toMbedtls(Algorithms.Min.BaseHashAlgo), hash.data(), hash.size(), resp.SignatureVector.data(), resp.SignatureVector.size());
	//	ret = mbedtls_pk_verify(&argh, toMbedtls(Algorithms.Min.BaseHashAlgo), hash.data(), hash.size(), resp.SignatureVector.data(), resp.SignatureVector.size());
		SPDMCPP_LOG_TRACE_RS(Log, ret);
		if (ret) {
			Log.iprint("mbedtls_pk_verify ret = ");
			Log.print(ret);
			Log.print(" = '");
			Log.print(mbedtls_high_level_strerr(ret));
			Log.println('\'');
		}
#else
    if (mbedtls_pk_get_type(&cert->pk) != MBEDTLS_PK_ECKEY)
    {
        assert(false);
    }
    mbedtls_ecdh_context* ctx = new mbedtls_ecdh_context;
    memset(ctx, 0, sizeof(*ctx));
    mbedtls_ecdh_init(ctx);

    int ret = mbedtls_ecdh_get_params(ctx, mbedtls_pk_ec(cert->pk),
                                      MBEDTLS_ECDH_OURS);
    if (ret != 0)
    {
        mbedtls_ecdh_free(ctx);
        delete ctx;
        assert(false);
    }

    size_t halfSize = 0;

    switch (ctx->grp.id)
    {
        case MBEDTLS_ECP_DP_SECP256R1:
            halfSize = 32;
            break;
        case MBEDTLS_ECP_DP_SECP384R1:
            halfSize = 48;
            break;
        case MBEDTLS_ECP_DP_SECP521R1:
            halfSize = 66;
            break;
        default:
            assert(false);
    }
    if (signature.size() != halfSize * 2)
    {
        assert(false);
    }

    mbedtls_mpi bnR, bnS;
    mbedtls_mpi_init(&bnR);
    mbedtls_mpi_init(&bnS);

    ret = mbedtls_mpi_read_binary(&bnR, signature.data(), halfSize);
    if (ret != 0)
    {
        mbedtls_mpi_free(&bnR);
        mbedtls_mpi_free(&bnS);
        assert(false);
    }
    ret = mbedtls_mpi_read_binary(&bnS, signature.data() + halfSize, halfSize);
    if (ret != 0)
    {
        mbedtls_mpi_free(&bnR);
        mbedtls_mpi_free(&bnS);
        assert(false);
    }
    ret = mbedtls_ecdsa_verify(&ctx->grp, hash.data(), hash.size(), &ctx->Q,
                               &bnR, &bnS);
    mbedtls_mpi_free(&bnR);
    mbedtls_mpi_free(&bnS);

    return ret;
#endif
}
} // namespace spdmcpp
