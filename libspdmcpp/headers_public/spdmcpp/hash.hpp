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
#include "mbedtls_support.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>
#include <vector>

namespace spdmcpp
{

inline HashEnum toHash(BaseHashAlgoFlags flags)
{
    SPDMCPP_ASSERT(countBits(flags) <= 1);
    switch (flags)
    {
        case BaseHashAlgoFlags::TPM_ALG_SHA_256:
            return HashEnum::TPM_ALG_SHA_256;
        case BaseHashAlgoFlags::TPM_ALG_SHA_384:
            return HashEnum::TPM_ALG_SHA_384;
        case BaseHashAlgoFlags::TPM_ALG_SHA_512:
            return HashEnum::TPM_ALG_SHA_512;
            // 			case BaseHashAlgoFlags::TPM_ALG_SHA3_256:	return
            // HashEnum::TPM_ALG_SHA_;	//TODO support for SHA3 missing from mbedtls...
            // 			case BaseHashAlgoFlags::TPM_ALG_SHA3_384:	return
            // HashEnum::TPM_ALG_SHA_;
            // 			case BaseHashAlgoFlags::TPM_ALG_SHA3_512:	return
            // HashEnum::TPM_ALG_SHA_;
        default:
            return HashEnum::INVALID;
    }
}

inline HashEnum toHash(MeasurementHashAlgoFlags flags)
{
    SPDMCPP_ASSERT(countBits(flags) <= 1);
    switch (flags)
    {
        case MeasurementHashAlgoFlags::RAW_BIT_STREAM_ONLY:
            return HashEnum::NONE;
        case MeasurementHashAlgoFlags::TPM_ALG_SHA_256:
            return HashEnum::TPM_ALG_SHA_256;
        case MeasurementHashAlgoFlags::TPM_ALG_SHA_384:
            return HashEnum::TPM_ALG_SHA_384;
        case MeasurementHashAlgoFlags::TPM_ALG_SHA_512:
            return HashEnum::TPM_ALG_SHA_512;
            // 			case MeasurementHashAlgoFlags::TPM_ALG_SHA3_256:
            // return HashEnum::TPM_ALG_SHA_;	//TODO support for SHA3 missing from
            // mbedtls... 			case
            // MeasurementHashAlgoFlags::TPM_ALG_SHA3_384: return
            // HashEnum::TPM_ALG_SHA_; 			case
            // MeasurementHashAlgoFlags::TPM_ALG_SHA3_512: return
            // HashEnum::TPM_ALG_SHA_;
        default:
            return HashEnum::INVALID;
    }
}

inline mbedtls_md_type_t toMbedtls(HashEnum algo)
{
    switch (algo)
    {
        case HashEnum::TPM_ALG_SHA_256:
            return MBEDTLS_MD_SHA256;
        case HashEnum::TPM_ALG_SHA_384:
            return MBEDTLS_MD_SHA384;
        case HashEnum::TPM_ALG_SHA_512:
            return MBEDTLS_MD_SHA512;
        // TODO support for SHA3 missing from mbedtls...
        default:
            return MBEDTLS_MD_NONE;
    }
}

/** @class HashClass
 *  @brief Abstraction for hashing data
 *  @details For trivial cases HashClass::compute() can be used directly.
 *  For more complicated usage patterns the following flow should be used:
 *    HashClass hc;
 *    hc.setup(HashEnum::TPM_ALG_SHA_256);
 *    hc.update(data);
 *    ...
 *    hc.update(data);
 *
 *    std::vector<uint8_t> hash_value;
 *    hc.hashFinish(hash_value);
 */
class HashClass
{
  public:
    /** @brief static method for quickly computing a hash for a buffer
     *  @param[out] hash - The computed hash
     *  @param[in] algo - The hash algorithm to use
     *  @param[in] buf - Pointer to the data for which the hash is computed
     *  @param[in] buf - Size of the data (in bytes)
     */
    static void compute(std::vector<uint8_t>& hash, HashEnum algo,
                        const uint8_t* buf, size_t size)
    {
        HashClass ha;
        ha.setup(algo);
        ha.update(buf, size);
        ha.hashFinish(hash);
    }

    /** @brief static method for quickly computing a hash for a buffer
     *  @param[out] hash - The computed hash
     *  @param[in] algo - The hash algorithm to use
     *  @param[in] buf - vector containing data for which the hash is computed
     *  @param[in] off - offset into the vector where the data should be read
     * from (must be < buf.size()) defaults to 0, a.k.a. start of the buffer
     *  @param[in] len - length of the data which will be hashed, by default
     * buffer is read until the end
     */
    static void compute(std::vector<uint8_t>& hash, HashEnum algo,
                        const std::vector<uint8_t>& buf, size_t off = 0,
                        size_t len = std::numeric_limits<size_t>::max())
    {
        SPDMCPP_ASSERT(off <= buf.size());
        if (len != std::numeric_limits<size_t>::max())
        {
            SPDMCPP_ASSERT(off + len <= buf.size());
        }
        compute(hash, algo, &buf[off], std::min(buf.size() - off, len));
    }

    /** @brief basic constructor
     *  @details setup(algo) should be used afterwards
     */
    HashClass()
    {
        mbedtls_md_init(&Ctx);
    }

    /** @brief copy constructor, which clones the running state of the hash
     */
    HashClass(const HashClass& other)
    {
        *this = other;
    }

    /** @brief asignment operator, which clones the running state of the hash
     */
    HashClass& operator=(const HashClass& other)
    {
        if (this == &other)
        {
            return *this;
        }
        mbedtls_md_init(&Ctx);
        // TODO failure possible?
        mbedtls_md_setup(&Ctx, other.getInfo(), 0);
        // TODO failure possible?
        mbedtls_md_clone(&Ctx, &other.Ctx);
        return *this;
    }

    HashClass(HashClass&&) = delete;
    HashClass& operator=(HashClass&&) = delete;

    ~HashClass()
    {
        mbedtls_md_free(&Ctx);
    }

    /** @brief function used to setup a hash
     *  @details should be called after the basic constructor or hashFinish()
     */
    void setup(HashEnum algo)
    {
        algorithm = algo;
        // TODO failure possible?
        mbedtls_md_setup(&Ctx, getInfo(), 0);
        // TODO failure possible?
        mbedtls_md_starts(&Ctx);
    }

    /** @brief function used to continue computing the hash with the given data
     */
    void update(const uint8_t* buf, size_t size)
    {
        // TODO failure possible?
        mbedtls_md_update(&Ctx, buf, size);
    }

    /** @brief function used to continue computing the hash with the given data
     */
    [[nodiscard]] RetStat update(const std::vector<uint8_t>& buf, size_t off = 0,
                size_t len = std::numeric_limits<size_t>::max())
    {
        if (off > buf.size())
        {
            std::cerr << "Wrong offset in the buffer: off = " << off <<", buf.size() = " << buf.size() << std::endl;
            return RetStat::ERROR_BUFFER_TOO_SMALL;
        }
        len = std::min(len, buf.size() - off);
        if (len > 0)
        {
            mbedtls_md_update(&Ctx, &buf[off], len);
        }
        return RetStat::OK;
    }

    /** @brief function used to finish computing the hash and writing it out
     *  @param[out] buf - pointer to the memory where the hash should be stored
     *  @param[in] size - size of the memory buffer, must match the hash size
     */
    void hashFinish(uint8_t* buf, size_t size)
    {
        SPDMCPP_ASSERT(mbedtls_md_get_size(getInfo()) == size);
        // TODO failure possible?
        mbedtls_md_finish(&Ctx, buf);
    }

    /** @brief function used to finish computing the hash and writing it out
     *  @param[out] buf - vector where the hash should be stored, will be
     * resized accordingly
     */
    void hashFinish(std::vector<uint8_t>& buf)
    {
        buf.resize(mbedtls_md_get_size(getInfo()));
        hashFinish(buf.data(), buf.size());
    }

  private:
    mbedtls_md_context_t Ctx{};
    HashEnum algorithm = HashEnum::NONE;

    const mbedtls_md_info_t* getInfo() const
    {
        return mbedtls_md_info_from_type(toMbedtls(algorithm));
    }
};

} // namespace spdmcpp
