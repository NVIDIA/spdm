
#pragma once

#include "assert.hpp"
#include "common.hpp"
#include "enum.hpp"
#include "flag.hpp"

#include <mbedtls/md.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>
#include <vector>

namespace spdmcpp
{

inline SignatureEnum toSignature(BaseAsymAlgoFlags flags)
{
    SPDMCPP_ASSERT(countBits(flags) <= 1);
    switch (flags)
    {
        case BaseAsymAlgoFlags::TPM_ALG_RSASSA_2048:
            return SignatureEnum::TPM_ALG_RSASSA_2048;
        case BaseAsymAlgoFlags::TPM_ALG_RSAPSS_2048:
            return SignatureEnum::TPM_ALG_RSAPSS_2048;
        case BaseAsymAlgoFlags::TPM_ALG_RSASSA_3072:
            return SignatureEnum::TPM_ALG_RSASSA_3072;
        case BaseAsymAlgoFlags::TPM_ALG_RSAPSS_3072:
            return SignatureEnum::TPM_ALG_RSAPSS_3072;
        case BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P256:
            return SignatureEnum::TPM_ALG_ECDSA_ECC_NIST_P256;
        case BaseAsymAlgoFlags::TPM_ALG_RSASSA_4096:
            return SignatureEnum::TPM_ALG_RSASSA_4096;
        case BaseAsymAlgoFlags::TPM_ALG_RSAPSS_4096:
            return SignatureEnum::TPM_ALG_RSAPSS_4096;
        case BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P384:
            return SignatureEnum::TPM_ALG_ECDSA_ECC_NIST_P384;
        case BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P521:
            return SignatureEnum::TPM_ALG_ECDSA_ECC_NIST_P521;
        default:
            return SignatureEnum::INVALID;
    }
}

} // namespace spdmcpp
