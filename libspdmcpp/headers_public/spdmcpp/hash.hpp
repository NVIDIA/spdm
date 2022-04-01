
#pragma once

#include "common.hpp"
#include "enum.hpp"
#include "flag.hpp"

#include <mbedtls/md.h>

#include <array>
#include <cassert>
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
    assert(countBits(static_cast<std::underlying_type_t<BaseHashAlgoFlags>>(
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
    assert(
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
        assert(off <= buf.size());
        if (len != std::numeric_limits<size_t>::max())
        {
            assert(off + len <= buf.size());
        }
        compute(hash, algo, buf.data() + off, std::min(buf.size() - off, len));
    }

    HashClass()
    {
        mbedtls_md_init(&Ctx);
    }
    HashClass(const HashClass& other)
    {
        mbedtls_md_init(&Ctx);
        int ret = mbedtls_md_setup(
            &Ctx, Ctx.md_info, 0); // TODO md_info may be considered private?!
        assert(ret == 0);          // TODO failure possible?
        ret = mbedtls_md_clone(&Ctx, &other.Ctx);
        assert(ret == 0); // TODO failure possible?
    }
    ~HashClass()
    {
        mbedtls_md_free(&Ctx);
    }

    void setup(HashEnum algo)
    {
        mbedtls_md_type_t type = toMbedtls(algo);
        int ret = mbedtls_md_setup(&Ctx, mbedtls_md_info_from_type(type), 0);
        assert(ret == 0); // TODO failure possible?
        ret = mbedtls_md_starts(&Ctx);
        assert(ret == 0); // TODO failure possible?
    }

    void update(const uint8_t* buf, size_t size)
    {
        int ret = mbedtls_md_update(&Ctx, buf, size);
        assert(ret == 0); // TODO failure possible?
    }
    void update(const std::vector<uint8_t>& buf, size_t off = 0,
                size_t len = std::numeric_limits<size_t>::max())
    {
        assert(off < buf.size());
        len = std::min(len, buf.size() - off);
        assert(off + len <= buf.size());
        int ret = mbedtls_md_update(&Ctx, buf.data() + off, len);
        assert(ret == 0); // TODO failure possible?
    }

    //	void hash_output(uint8_t* buf, size_t size)

    void hashFinish(uint8_t* buf, size_t size)
    {
        assert(mbedtls_md_get_size(Ctx.md_info) == size);
        int ret = mbedtls_md_finish(&Ctx, buf);
        assert(ret == 0); // TODO failure possible?
        //	ret = mbedtls_md_starts(&Ctx);
        //	assert(ret == 0);//TODO failure possible?
    }
    void hashFinish(std::vector<uint8_t>& buf)
    {
        buf.resize(mbedtls_md_get_size(Ctx.md_info));
        hashFinish(buf.data(), buf.size());
    }

  private:
    mbedtls_md_context_t Ctx;
};

} // namespace spdmcpp
