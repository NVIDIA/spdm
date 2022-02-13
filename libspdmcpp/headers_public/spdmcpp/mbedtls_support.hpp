
#pragma once

#include "flag.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

namespace spdmcpp
{

mbedtls_md_type_t to_mbedtls(BaseHashAlgoFlags flags)
{
    assert(count_bits(static_cast<std::underlying_type_t<BaseHashAlgoFlags>>(
               flags)) <= 1);
    switch (flags)
    {
        case BaseHashAlgoFlags::TPM_ALG_SHA_256:
            return MBEDTLS_MD_SHA256;
        case BaseHashAlgoFlags::TPM_ALG_SHA_384:
            return MBEDTLS_MD_SHA384;
        case BaseHashAlgoFlags::TPM_ALG_SHA_512:
            return MBEDTLS_MD_SHA512; // TODO figure out difference between SHA
                                      // and SHA3 here...
        case BaseHashAlgoFlags::TPM_ALG_SHA3_256:
            return MBEDTLS_MD_SHA256; // TODO
        case BaseHashAlgoFlags::TPM_ALG_SHA3_384:
            return MBEDTLS_MD_SHA384;
        case BaseHashAlgoFlags::TPM_ALG_SHA3_512:
            return MBEDTLS_MD_SHA512;
        default:
            return MBEDTLS_MD_NONE;
    }
}

mbedtls_md_type_t to_mbedtls(MeasurementHashAlgoFlags flags)
{
    assert(count_bits(
               static_cast<std::underlying_type_t<MeasurementHashAlgoFlags>>(
                   flags)) <= 1);
    switch (flags)
    {
        case MeasurementHashAlgoFlags::RAW_BIT_STREAM_ONLY:
            return MBEDTLS_MD_NONE;
        case MeasurementHashAlgoFlags::TPM_ALG_SHA_256:
            return MBEDTLS_MD_SHA256;
        case MeasurementHashAlgoFlags::TPM_ALG_SHA_384:
            return MBEDTLS_MD_SHA384;
        case MeasurementHashAlgoFlags::TPM_ALG_SHA_512:
            return MBEDTLS_MD_SHA512; // TODO figure out difference between SHA
                                      // and SHA3 here...
        case MeasurementHashAlgoFlags::TPM_ALG_SHA3_256:
            return MBEDTLS_MD_SHA256; // TODO
        case MeasurementHashAlgoFlags::TPM_ALG_SHA3_384:
            return MBEDTLS_MD_SHA384;
        case MeasurementHashAlgoFlags::TPM_ALG_SHA3_512:
            return MBEDTLS_MD_SHA512;
        default:
            return MBEDTLS_MD_NONE;
    }
}

inline int verify_signature(mbedtls_x509_crt* cert,
                            const std::vector<uint8_t>& signature,
                            const std::vector<uint8_t>& hash)
{
#if 0
		mbedtls_pk_context argh;
		mbedtls_pk_init(&argh);
		mbedtls_pk_setup(&argh, cert->pk.pk_info);
		ret = mbedtls_pk_verify(&cert->pk, to_mbedtls(Algorithms.Min.BaseHashAlgo), hash.data(), hash.size(), resp.SignatureVector.data(), resp.SignatureVector.size());
	//	ret = mbedtls_pk_verify(&argh, to_mbedtls(Algorithms.Min.BaseHashAlgo), hash.data(), hash.size(), resp.SignatureVector.data(), resp.SignatureVector.size());
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

    size_t half_size = 0;

    switch (ctx->grp.id)
    {
        case MBEDTLS_ECP_DP_SECP256R1:
            half_size = 32;
            break;
        case MBEDTLS_ECP_DP_SECP384R1:
            half_size = 48;
            break;
        case MBEDTLS_ECP_DP_SECP521R1:
            half_size = 66;
            break;
        default:
            assert(false);
    }
    if (signature.size() != half_size * 2)
    {
        assert(false);
    }

    mbedtls_mpi bn_r, bn_s;
    mbedtls_mpi_init(&bn_r);
    mbedtls_mpi_init(&bn_s);

    ret = mbedtls_mpi_read_binary(&bn_r, signature.data(), half_size);
    if (ret != 0)
    {
        mbedtls_mpi_free(&bn_r);
        mbedtls_mpi_free(&bn_s);
        assert(false);
    }
    ret =
        mbedtls_mpi_read_binary(&bn_s, signature.data() + half_size, half_size);
    if (ret != 0)
    {
        mbedtls_mpi_free(&bn_r);
        mbedtls_mpi_free(&bn_s);
        assert(false);
    }
    ret = mbedtls_ecdsa_verify(&ctx->grp, hash.data(), hash.size(), &ctx->Q,
                               &bn_r, &bn_s);
    mbedtls_mpi_free(&bn_r);
    mbedtls_mpi_free(&bn_s);

    return ret;
#endif
}
} // namespace spdmcpp
