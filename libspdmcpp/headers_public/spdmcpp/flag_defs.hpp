/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
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





#include "flag.hpp"

#ifdef SPDMCPP_FLAG_HPP // this is necessary to avoid issues with clang-tidy etc
                        // being run for this header

// CAPABILITIES

FLAG_START(RequesterCapabilitiesFlags, uint32_t)
FLAG_VALUE(RequesterCapabilitiesFlags, NIL, 0)
FLAG_VALUE(RequesterCapabilitiesFlags, RESERVED, 1 << 0)
FLAG_VALUE(RequesterCapabilitiesFlags, CERT_CAP, 1 << 1)
FLAG_VALUE(RequesterCapabilitiesFlags, CHAL_CAP, 1 << 2)
FLAG_VALUE(RequesterCapabilitiesFlags, MEAS_CAP, 3 << 3)
FLAG_VALUE(RequesterCapabilitiesFlags, MEAS_CAP_01, 1 << 3)
FLAG_VALUE(RequesterCapabilitiesFlags, MEAS_CAP_10, 2 << 3)
FLAG_VALUE(RequesterCapabilitiesFlags, MEAS_FRESH_CAP, 1 << 5)
FLAG_VALUE(RequesterCapabilitiesFlags, ENCRYPT_CAP, 1 << 6)
FLAG_VALUE(RequesterCapabilitiesFlags, MAC_CAP, 1 << 7)
FLAG_VALUE(RequesterCapabilitiesFlags, MUT_AUTH_CAP, 1 << 8)
FLAG_VALUE(RequesterCapabilitiesFlags, KEY_EX_CAP, 1 << 9)
FLAG_VALUE(RequesterCapabilitiesFlags, PSK_CAP, 3 << 10)
FLAG_VALUE(RequesterCapabilitiesFlags, PSK_CAP_01, 1 << 10)
FLAG_VALUE(RequesterCapabilitiesFlags, PSK_CAP_10, 2 << 10)
FLAG_VALUE(RequesterCapabilitiesFlags, ENCAP_CAP, 1 << 12)
FLAG_VALUE(RequesterCapabilitiesFlags, HBEAT_CAP, 1 << 13)
FLAG_VALUE(RequesterCapabilitiesFlags, KEY_UPD_CAP, 1 << 14)
FLAG_VALUE(RequesterCapabilitiesFlags, HANDSHAKE_IN_THE_CLEAR_CAP, 1 << 15)
FLAG_VALUE(RequesterCapabilitiesFlags, PUB_KEY_ID_CAP, 1 << 16)
FLAG_END(RequesterCapabilitiesFlags, uint32_t)

FLAG_START(ResponderCapabilitiesFlags, uint32_t)
FLAG_VALUE(ResponderCapabilitiesFlags, NIL, 0)
FLAG_VALUE(ResponderCapabilitiesFlags, CACHE_CAP, 1 << 0)
FLAG_VALUE(ResponderCapabilitiesFlags, CERT_CAP, 1 << 1)
FLAG_VALUE(ResponderCapabilitiesFlags, CHAL_CAP, 1 << 2)
FLAG_VALUE(ResponderCapabilitiesFlags, MEAS_CAP, 3 << 3)
FLAG_VALUE(ResponderCapabilitiesFlags, MEAS_CAP_01, 1 << 3)
FLAG_VALUE(ResponderCapabilitiesFlags, MEAS_CAP_10, 2 << 3)
FLAG_VALUE(ResponderCapabilitiesFlags, MEAS_FRESH_CAP, 1 << 5)
FLAG_VALUE(ResponderCapabilitiesFlags, ENCRYPT_CAP, 1 << 6)
FLAG_VALUE(ResponderCapabilitiesFlags, MAC_CAP, 1 << 7)
FLAG_VALUE(ResponderCapabilitiesFlags, MUT_AUTH_CAP, 1 << 8)
FLAG_VALUE(ResponderCapabilitiesFlags, KEY_EX_CAP, 1 << 9)
FLAG_VALUE(ResponderCapabilitiesFlags, PSK_CAP, 3 << 10)
FLAG_VALUE(ResponderCapabilitiesFlags, PSK_CAP_01, 1 << 10)
FLAG_VALUE(ResponderCapabilitiesFlags, PSK_CAP_10, 2 << 10)
FLAG_VALUE(ResponderCapabilitiesFlags, ENCAP_CAP, 1 << 12)
FLAG_VALUE(ResponderCapabilitiesFlags, HBEAT_CAP, 1 << 13)
FLAG_VALUE(ResponderCapabilitiesFlags, KEY_UPD_CAP, 1 << 14)
FLAG_VALUE(ResponderCapabilitiesFlags, HANDSHAKE_IN_THE_CLEAR_CAP, 1 << 15)
FLAG_VALUE(ResponderCapabilitiesFlags, PUB_KEY_ID_CAP, 1 << 16)
FLAG_END(ResponderCapabilitiesFlags, uint32_t)

// ALGORITHMS
/*
FLAG_START(MeasurementSpecificationFlags, uint8_t)
FLAG_VALUE(MeasurementSpecificationFlags, NIL, 0) FLAG_VALUE(BaseHashAlgoFlags,
TPM_ALG_SHA_256,						1 << 0) FLAG_VALUE(BaseHashAlgoFlags,
TPM_ALG_SHA_384,						1 << 1) FLAG_VALUE(BaseHashAlgoFlags,
TPM_ALG_SHA_512,						1 << 2) FLAG_VALUE(BaseHashAlgoFlags,
TPM_ALG_SHA3_256,						1 << 3) FLAG_VALUE(BaseHashAlgoFlags,
TPM_ALG_SHA3_384,						1 << 4) FLAG_VALUE(BaseHashAlgoFlags,
TPM_ALG_SHA3_512,						1 << 5) FLAG_END(BaseHashAlgoFlags,
uint32_t)
*/

FLAG_START(BaseAsymAlgoFlags, uint32_t)
FLAG_VALUE(BaseAsymAlgoFlags, NIL, 0)
FLAG_VALUE(BaseAsymAlgoFlags, TPM_ALG_RSASSA_2048, 1 << 0)
FLAG_VALUE(BaseAsymAlgoFlags, TPM_ALG_RSAPSS_2048, 1 << 1)
FLAG_VALUE(BaseAsymAlgoFlags, TPM_ALG_RSASSA_3072, 1 << 2)
FLAG_VALUE(BaseAsymAlgoFlags, TPM_ALG_RSAPSS_3072, 1 << 3)
FLAG_VALUE(BaseAsymAlgoFlags, TPM_ALG_ECDSA_ECC_NIST_P256, 1 << 4)
FLAG_VALUE(BaseAsymAlgoFlags, TPM_ALG_RSASSA_4096, 1 << 5)
FLAG_VALUE(BaseAsymAlgoFlags, TPM_ALG_RSAPSS_4096, 1 << 6)
FLAG_VALUE(BaseAsymAlgoFlags, TPM_ALG_ECDSA_ECC_NIST_P384, 1 << 7)
FLAG_VALUE(BaseAsymAlgoFlags, TPM_ALG_ECDSA_ECC_NIST_P521, 1 << 8)
FLAG_END(BaseAsymAlgoFlags, uint32_t)

FLAG_START(BaseHashAlgoFlags, uint32_t)
FLAG_VALUE(BaseHashAlgoFlags, NIL, 0)
FLAG_VALUE(BaseHashAlgoFlags, TPM_ALG_SHA_256, 1 << 0)
FLAG_VALUE(BaseHashAlgoFlags, TPM_ALG_SHA_384, 1 << 1)
FLAG_VALUE(BaseHashAlgoFlags, TPM_ALG_SHA_512, 1 << 2)
FLAG_VALUE(BaseHashAlgoFlags, TPM_ALG_SHA3_256, 1 << 3)
FLAG_VALUE(BaseHashAlgoFlags, TPM_ALG_SHA3_384, 1 << 4)
FLAG_VALUE(BaseHashAlgoFlags, TPM_ALG_SHA3_512, 1 << 5)
FLAG_END(BaseHashAlgoFlags, uint32_t)

FLAG_START(MeasurementHashAlgoFlags, uint32_t)
FLAG_VALUE(MeasurementHashAlgoFlags, NIL, 0)
FLAG_VALUE(MeasurementHashAlgoFlags, RAW_BIT_STREAM_ONLY, 1 << 0)
FLAG_VALUE(MeasurementHashAlgoFlags, TPM_ALG_SHA_256, 1 << 1)
FLAG_VALUE(MeasurementHashAlgoFlags, TPM_ALG_SHA_384, 1 << 2)
FLAG_VALUE(MeasurementHashAlgoFlags, TPM_ALG_SHA_512, 1 << 3)
FLAG_VALUE(MeasurementHashAlgoFlags, TPM_ALG_SHA3_256, 1 << 4)
FLAG_VALUE(MeasurementHashAlgoFlags, TPM_ALG_SHA3_384, 1 << 5)
FLAG_VALUE(MeasurementHashAlgoFlags, TPM_ALG_SHA3_512, 1 << 6)
FLAG_END(MeasurementHashAlgoFlags, uint32_t)

#endif
