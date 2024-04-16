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

/*
 * Copyright (C) NVIDIA Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
