
#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <limits>

#include "flag.hpp"

namespace spdmcpp
{
	
	mbedtls_md_type_t to_mbedtls(BaseHashAlgoFlags flags)
	{
		assert(count_bits(static_cast<std::underlying_type_t<BaseHashAlgoFlags>>(flags)) <= 1);
		switch (flags) {
			case BaseHashAlgoFlags::TPM_ALG_SHA_256:	return MBEDTLS_MD_SHA256;
			case BaseHashAlgoFlags::TPM_ALG_SHA_384:	return MBEDTLS_MD_SHA384;
			case BaseHashAlgoFlags::TPM_ALG_SHA_512:	return MBEDTLS_MD_SHA512;//TODO figure out difference between SHA and SHA3 here...
			case BaseHashAlgoFlags::TPM_ALG_SHA3_256:	return MBEDTLS_MD_SHA256;//TODO 
			case BaseHashAlgoFlags::TPM_ALG_SHA3_384:	return MBEDTLS_MD_SHA384;
			case BaseHashAlgoFlags::TPM_ALG_SHA3_512:	return MBEDTLS_MD_SHA512;
			default:									return MBEDTLS_MD_NONE;
		}
	}
	
	mbedtls_md_type_t to_mbedtls(MeasurementHashAlgoFlags flags)
	{
		assert(count_bits(static_cast<std::underlying_type_t<MeasurementHashAlgoFlags>>(flags)) <= 1);
		switch (flags) {
			case MeasurementHashAlgoFlags::RAW_BIT_STREAM_ONLY:	return MBEDTLS_MD_NONE;
			case MeasurementHashAlgoFlags::TPM_ALG_SHA_256:		return MBEDTLS_MD_SHA256;
			case MeasurementHashAlgoFlags::TPM_ALG_SHA_384:		return MBEDTLS_MD_SHA384;
			case MeasurementHashAlgoFlags::TPM_ALG_SHA_512:		return MBEDTLS_MD_SHA512;//TODO figure out difference between SHA and SHA3 here...
			case MeasurementHashAlgoFlags::TPM_ALG_SHA3_256:	return MBEDTLS_MD_SHA256;//TODO 
			case MeasurementHashAlgoFlags::TPM_ALG_SHA3_384:	return MBEDTLS_MD_SHA384;
			case MeasurementHashAlgoFlags::TPM_ALG_SHA3_512:	return MBEDTLS_MD_SHA512;
			default:											return MBEDTLS_MD_NONE;
		}
	}
	
}
