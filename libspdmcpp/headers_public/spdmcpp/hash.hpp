
#pragma once

#include "common.hpp"

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
class HashClass
{
  public:
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

    void setup(mbedtls_md_type_t type)
    {
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

    void hash_finish(uint8_t* buf, size_t size)
    {
        assert(mbedtls_md_get_size(Ctx.md_info) == size);
        int ret = mbedtls_md_finish(&Ctx, buf);
        assert(ret == 0); // TODO failure possible?
        //	ret = mbedtls_md_starts(&Ctx);
        //	assert(ret == 0);//TODO failure possible?
    }
    void hash_finish(std::vector<uint8_t>& buf)
    {
        buf.resize(mbedtls_md_get_size(Ctx.md_info));
        hash_finish(buf.data(), buf.size());
    }

  private:
    mbedtls_md_context_t Ctx;
};

} // namespace spdmcpp
