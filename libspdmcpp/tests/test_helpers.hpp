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





#include <spdmcpp/assert.hpp>
#include <spdmcpp/helpers.hpp>
#include <spdmcpp/mbedtls_support.hpp>

#include <fstream>
#include <iostream>

constexpr std::mt19937::result_type mt19937DefaultSeed = 13;

inline void
    fillPseudoRandom(std::span<uint8_t, std::dynamic_extent> buf,
                     std::mt19937::result_type seed = mt19937DefaultSeed)
{
    std::mt19937 gen(seed);
    std::uniform_int_distribution<uint8_t> distrib(1);

    std::generate(buf.begin(), buf.end(), [&]() { return distrib(gen); });
}

template <typename T>
inline void
    fillPseudoRandomType(T& dst,
                         std::mt19937::result_type seed = mt19937DefaultSeed)
{
    // NOLINTNEXTLINE cppcoreguidelines-pro-type-reinterpret-cast
    fillPseudoRandom(std::span(reinterpret_cast<uint8_t*>(&dst), sizeof(dst)),
                     seed);
}

template <typename T>
inline T
    returnPseudoRandomType(std::mt19937::result_type seed = mt19937DefaultSeed)
{
    T dst{};
    fillPseudoRandomType(dst, seed);
    return dst;
}

inline void loadFile(std::vector<uint8_t>& buf, const std::string& str)
{
    std::ifstream file;
    buf.clear();
    file.open(str, std::ios::in | std::ios::ate | std::ios::binary);

    buf.resize(file.tellg());
    file.seekg(0, std::ios::beg);
    // NOLINTNEXTLINE cppcoreguidelines-pro-type-reinterpret-cast
    file.read(reinterpret_cast<char*>(buf.data()), buf.size());
    file.close();
}

inline void appendFile(std::vector<uint8_t>& buf, const std::string& str)
{
    std::ifstream file;
    file.open(str, std::ios::in | std::ios::ate | std::ios::binary);

    size_t off = buf.size();
    size_t fileSize = file.tellg();
    buf.resize(off + fileSize);
    file.seekg(0, std::ios::beg);
    // NOLINTNEXTLINE cppcoreguidelines-pro-type-reinterpret-cast
    file.read(reinterpret_cast<char*>(&buf[off]), fileSize);
    file.close();
}

inline int fRng(void* /*ctx*/, unsigned char* buf, size_t len)
{
    spdmcpp::fillRandom(std::span(buf, len));
    return 0;
}

inline int computeSignature(mbedtls_pk_context* pkctx,
                            std::vector<uint8_t>& signature,
                            const std::vector<uint8_t>& message)
{
    if (mbedtls_pk_get_type(pkctx) != MBEDTLS_PK_ECKEY)
    {
        SPDMCPP_ASSERT(false);
    }

    mbedtls_ecp_keypair* ctx = mbedtls_pk_ec(*pkctx);

    spdmcpp::mbedtls_mpi_raii sigR, sigS;

    int ret = mbedtls_ecdsa_sign(&ctx->grp, sigR, sigS, &ctx->d, message.data(),
                                 message.size(), fRng, nullptr);
    if (ret)
    {
        return ret;
    }
    size_t halfSize = spdmcpp::getHalfSize(*ctx);
    signature.resize(halfSize * 2);
    ret = mbedtls_mpi_write_binary(sigR, signature.data(), halfSize);
    SPDMCPP_ASSERT(!ret);
    ret = mbedtls_mpi_write_binary(sigS, &signature[halfSize], halfSize);
    SPDMCPP_ASSERT(!ret);

    return ret;
}

inline int computeSignature(mbedtls_x509_crt* cert,
                            std::vector<uint8_t>& signature,
                            const std::vector<uint8_t>& message)
{
    return computeSignature(&cert->pk, signature, message);
}
