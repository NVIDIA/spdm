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






#include "str_conv.hpp"

namespace spdmt {

using namespace spdmcpp;

std::string verToString(const PacketVersionNumber& ver)
{
    return std::to_string(ver.getMajor()) + "." +
           std::to_string(ver.getMinor());
}

std::string verToString(MessageVersionEnum ver)
{
    auto val = static_cast<std::underlying_type_t<MessageVersionEnum>>(ver);
    return std::to_string(val >> 4) + "." + std::to_string(val & 0x0f);
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define xstr(s) #s

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define CAP_FLAGS_STR(x)                                                       \
    do                                                                         \
    {                                                                          \
        if ((flags & ResponderCapabilitiesFlags::x) ==                         \
            ResponderCapabilitiesFlags::x)                                     \
        {                                                                      \
            ret.emplace_back(xstr(x));                                         \
        }                                                                      \
    } while (0)

std::vector<std::string> capFlagsToStr(ResponderCapabilitiesFlags flags)
{
    std::vector<std::string> ret;
    CAP_FLAGS_STR(CACHE_CAP);
    CAP_FLAGS_STR(CERT_CAP);
    CAP_FLAGS_STR(CHAL_CAP);
    CAP_FLAGS_STR(MEAS_CAP);
    CAP_FLAGS_STR(MEAS_CAP_01);
    CAP_FLAGS_STR(MEAS_CAP_10);
    CAP_FLAGS_STR(MEAS_FRESH_CAP);
    CAP_FLAGS_STR(ENCRYPT_CAP);
    CAP_FLAGS_STR(MAC_CAP);
    CAP_FLAGS_STR(MUT_AUTH_CAP);
    CAP_FLAGS_STR(KEY_EX_CAP);
    CAP_FLAGS_STR(PSK_CAP);
    CAP_FLAGS_STR(PSK_CAP_01);
    CAP_FLAGS_STR(PSK_CAP_10);
    CAP_FLAGS_STR(ENCAP_CAP);
    CAP_FLAGS_STR(HBEAT_CAP);
    CAP_FLAGS_STR(KEY_UPD_CAP);
    CAP_FLAGS_STR(HANDSHAKE_IN_THE_CLEAR_CAP);
    CAP_FLAGS_STR(PUB_KEY_ID_CAP);
    return ret;
}
#undef CAP_FLAGS_STR

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define HASH_FLAGS_STR(x)                                                      \
    do                                                                         \
    {                                                                          \
        if ((flags & BaseHashAlgoFlags::x) == BaseHashAlgoFlags::x)            \
        {                                                                      \
            return xstr(x);                                                    \
        }                                                                      \
    } while (0)

std::string hashAlgoToStr(BaseHashAlgoFlags flags)
{
    if (countBits(flags) > 1)
    {
        return "INVALID";
    }
    HASH_FLAGS_STR(TPM_ALG_SHA_256);
    HASH_FLAGS_STR(TPM_ALG_SHA_384);
    HASH_FLAGS_STR(TPM_ALG_SHA_512);
    HASH_FLAGS_STR(TPM_ALG_SHA3_256);
    HASH_FLAGS_STR(TPM_ALG_SHA3_384);
    HASH_FLAGS_STR(TPM_ALG_SHA3_512);
    return "";
}
#undef HASH_FLAGS_STR

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ASYM_FLAGS_STR(x)                                                      \
    do                                                                         \
    {                                                                          \
        if ((flags & BaseAsymAlgoFlags::x) == BaseAsymAlgoFlags::x)            \
        {                                                                      \
            return xstr(x);                                                    \
        }                                                                      \
    } while (0)


std::string asymAlgoToStr(BaseAsymAlgoFlags flags)
{
    if (countBits(flags) > 1)
    {
        return "INVALID";
    }
    ASYM_FLAGS_STR(TPM_ALG_RSASSA_2048);
    ASYM_FLAGS_STR(TPM_ALG_RSAPSS_2048);
    ASYM_FLAGS_STR(TPM_ALG_RSASSA_3072);
    ASYM_FLAGS_STR(TPM_ALG_RSAPSS_3072);
    ASYM_FLAGS_STR(TPM_ALG_ECDSA_ECC_NIST_P256);
    ASYM_FLAGS_STR(TPM_ALG_RSASSA_4096);
    ASYM_FLAGS_STR(TPM_ALG_RSAPSS_4096);
    ASYM_FLAGS_STR(TPM_ALG_ECDSA_ECC_NIST_P384);
    ASYM_FLAGS_STR(TPM_ALG_ECDSA_ECC_NIST_P521);
    return "";
}

#undef HASH_FLAGS_STR
#undef xstr


}