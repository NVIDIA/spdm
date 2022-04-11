
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
    SPDMCPP_ASSERT(
        countBits(static_cast<std::underlying_type_t<BaseHashAlgoFlags>>(
            flags)) <= 1);
    switch (flags)
    {
        case BaseHashAlgoFlags::TPM_ALG_SHA_256:
            return HashEnum::SHA_256;
        case BaseHashAlgoFlags::TPM_ALG_SHA_384:
            return HashEnum::SHA_384;
        case BaseHashAlgoFlags::TPM_ALG_SHA_512:
            return HashEnum::SHA_512;
            // 			case BaseHashAlgoFlags::TPM_ALG_SHA3_256:	return
            // HashEnum::SHA_;	//TODO support for SHA3 missing from mbedtls...
            // 			case BaseHashAlgoFlags::TPM_ALG_SHA3_384:	return
            // HashEnum::SHA_;
            // 			case BaseHashAlgoFlags::TPM_ALG_SHA3_512:	return
            // HashEnum::SHA_;
        default:
            return HashEnum::INVALID;
    }
}

inline HashEnum toHash(MeasurementHashAlgoFlags flags)
{
    SPDMCPP_ASSERT(
        countBits(static_cast<std::underlying_type_t<MeasurementHashAlgoFlags>>(
            flags)) <= 1);
    switch (flags)
    {
        case MeasurementHashAlgoFlags::RAW_BIT_STREAM_ONLY:
            return HashEnum::NONE;
        case MeasurementHashAlgoFlags::TPM_ALG_SHA_256:
            return HashEnum::SHA_256;
        case MeasurementHashAlgoFlags::TPM_ALG_SHA_384:
            return HashEnum::SHA_384;
        case MeasurementHashAlgoFlags::TPM_ALG_SHA_512:
            return HashEnum::SHA_512;
            // 			case MeasurementHashAlgoFlags::TPM_ALG_SHA3_256:
            // return HashEnum::SHA_;	//TODO support for SHA3 missing from
            // mbedtls... 			case
            // MeasurementHashAlgoFlags::TPM_ALG_SHA3_384: return
            // HashEnum::SHA_; 			case
            // MeasurementHashAlgoFlags::TPM_ALG_SHA3_512: return
            // HashEnum::SHA_;
        default:
            return HashEnum::INVALID;
    }
}

inline mbedtls_md_type_t toMbedtls(HashEnum algo)
{
    switch (algo)
    {
        case HashEnum::SHA_256:
            return MBEDTLS_MD_SHA256;
        case HashEnum::SHA_384:
            return MBEDTLS_MD_SHA384;
        case HashEnum::SHA_512:
            return MBEDTLS_MD_SHA512;
        // TODO support for SHA3 missing from mbedtls...
        default:
            return MBEDTLS_MD_NONE;
    }
}

class HashClass
{
  public:
    static void compute(std::vector<uint8_t>& hash, HashEnum algo,
                        const uint8_t* buf, size_t size)
    {
        HashClass ha;
        ha.setup(algo);
        ha.update(buf, size);
        ha.hashFinish(hash);
    }
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

    HashClass()
    {
        mbedtls_md_init(&Ctx);
    }
    HashClass(const HashClass& other)
    {
        *this = other;
    }
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
    }

    HashClass(HashClass&&) = delete;
    HashClass& operator=(HashClass&&) = delete;

    ~HashClass()
    {
        mbedtls_md_free(&Ctx);
    }

    void setup(HashEnum algo)
    {
        algorithm = algo;
        // TODO failure possible?
        mbedtls_md_setup(&Ctx, getInfo(), 0);
        // TODO failure possible?
        mbedtls_md_starts(&Ctx);
    }

    void update(const uint8_t* buf, size_t size)
    {
        // TODO failure possible?
        mbedtls_md_update(&Ctx, buf, size);
    }
    void update(const std::vector<uint8_t>& buf, size_t off = 0,
                size_t len = std::numeric_limits<size_t>::max())
    {
        SPDMCPP_ASSERT(off < buf.size());
        len = std::min(len, buf.size() - off);
        SPDMCPP_ASSERT(off + len <= buf.size());
        // TODO failure possible?
        mbedtls_md_update(&Ctx, &buf[off], len);
    }

    //	void hash_output(uint8_t* buf, size_t size)

    void hashFinish(uint8_t* buf, size_t size)
    {
        SPDMCPP_ASSERT(mbedtls_md_get_size(getInfo()) == size);
        // TODO failure possible?
        mbedtls_md_finish(&Ctx, buf);
    }
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
