/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
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

#include "cbor_det.hpp"

#include <cbor.h>

#include <algorithm>
#include <functional>
#include <stdexcept>

namespace spdmd::composite::cbor
{

namespace
{

/// Encode via tinycbor into a growable vector. tinycbor signals overflow
/// through get_extra_bytes_needed(); retry with a larger buffer.
std::vector<std::uint8_t>
    encodeToVec(const std::function<void(CborEncoder&)>& fn,
                std::size_t initial = 64)
{
    std::vector<std::uint8_t> buf(initial);
    for (int attempt = 0; attempt < 6; ++attempt)
    {
        CborEncoder enc;
        cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
        fn(enc);
        std::size_t extra = cbor_encoder_get_extra_bytes_needed(&enc);
        if (extra == 0)
        {
            buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
            return buf;
        }
        buf.resize(buf.size() + extra);
    }
    throw std::runtime_error("cbor_det: encode overflow");
}

/// Emit a definite-length container head (array/map) in shortest form.
/// tinycbor only writes container heads through create_array/create_map,
/// which buffer until close; for a header-only writer we mirror its
/// shortest-form output here. Major: 4=array, 5=map.
void putContainerHead(std::vector<std::uint8_t>& out, std::uint8_t major,
                      std::uint64_t n)
{
    const std::uint8_t mt = static_cast<std::uint8_t>(major << 5U);
    if (n < 24U)
    {
        out.push_back(static_cast<std::uint8_t>(mt | n));
    }
    else if (n <= 0xFFU)
    {
        out.push_back(static_cast<std::uint8_t>(mt | 24U));
        out.push_back(static_cast<std::uint8_t>(n));
    }
    else if (n <= 0xFFFFU)
    {
        out.push_back(static_cast<std::uint8_t>(mt | 25U));
        out.push_back(static_cast<std::uint8_t>((n >> 8U) & 0xFFU));
        out.push_back(static_cast<std::uint8_t>(n & 0xFFU));
    }
    else
    {
        out.push_back(static_cast<std::uint8_t>(mt | 26U));
        for (int s = 24; s >= 0; s -= 8)
        {
            out.push_back(static_cast<std::uint8_t>((n >> s) & 0xFFU));
        }
    }
}

} // namespace

void putUint(std::vector<std::uint8_t>& out, std::uint64_t v)
{
    auto e = encodeToVec([&](CborEncoder& enc) { cbor_encode_uint(&enc, v); });
    out.insert(out.end(), e.begin(), e.end());
}

void putInt(std::vector<std::uint8_t>& out, std::int64_t v)
{
    auto e = encodeToVec([&](CborEncoder& enc) { cbor_encode_int(&enc, v); });
    out.insert(out.end(), e.begin(), e.end());
}

void putBytes(std::vector<std::uint8_t>& out, std::span<const std::uint8_t> v)
{
    auto e = encodeToVec(
        [&](CborEncoder& enc) {
            cbor_encode_byte_string(&enc, v.data(), v.size());
        },
        v.size() + 16);
    out.insert(out.end(), e.begin(), e.end());
}

void putText(std::vector<std::uint8_t>& out, std::string_view v)
{
    auto e = encodeToVec(
        [&](CborEncoder& enc) {
            cbor_encode_text_string(&enc, v.data(), v.size());
        },
        v.size() + 16);
    out.insert(out.end(), e.begin(), e.end());
}

void putArrayHeader(std::vector<std::uint8_t>& out, std::size_t n)
{
    putContainerHead(out, 4, n);
}

void putMapHeader(std::vector<std::uint8_t>& out, std::size_t n)
{
    putContainerHead(out, 5, n);
}

void putTag(std::vector<std::uint8_t>& out, std::uint64_t tag)
{
    auto e = encodeToVec([&](CborEncoder& enc) { cbor_encode_tag(&enc, tag); });
    out.insert(out.end(), e.begin(), e.end());
}

std::vector<std::uint8_t> uintVal(std::uint64_t v)
{
    std::vector<std::uint8_t> o;
    putUint(o, v);
    return o;
}

std::vector<std::uint8_t> intVal(std::int64_t v)
{
    std::vector<std::uint8_t> o;
    putInt(o, v);
    return o;
}

std::vector<std::uint8_t> bytesVal(std::span<const std::uint8_t> v)
{
    std::vector<std::uint8_t> o;
    putBytes(o, v);
    return o;
}

std::vector<std::uint8_t> textVal(std::string_view v)
{
    std::vector<std::uint8_t> o;
    putText(o, v);
    return o;
}

std::vector<std::uint8_t>
    arrayVal(std::span<const std::vector<std::uint8_t>> elems)
{
    std::vector<std::uint8_t> out;
    putArrayHeader(out, elems.size());
    for (const auto& e : elems)
    {
        out.insert(out.end(), e.begin(), e.end());
    }
    return out;
}

void Map::addInt(std::int64_t key, std::vector<std::uint8_t> value)
{
    entries.emplace_back(intVal(key), std::move(value));
}

void Map::addText(std::string_view key, std::vector<std::uint8_t> value)
{
    entries.emplace_back(textVal(key), std::move(value));
}

std::vector<std::uint8_t> Map::encode() const
{
    // tinycbor produces shortest-form, definite-length items. The one
    // determinism rule it does not enforce is map-key ordering, so we
    // own that: sort by bytewise lexicographic order of the encoded key
    // (RFC 8949 §4.2.1), then concatenate header + key/value pairs.
    std::vector<
        const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>*>
        ordered;
    ordered.reserve(entries.size());
    for (const auto& e : entries)
    {
        ordered.push_back(&e);
    }
    std::sort(ordered.begin(), ordered.end(),
              [](const auto* a, const auto* b) { return a->first < b->first; });

    std::vector<std::uint8_t> out;
    putMapHeader(out, ordered.size());
    for (const auto* e : ordered)
    {
        out.insert(out.end(), e->first.begin(), e->first.end());
        out.insert(out.end(), e->second.begin(), e->second.end());
    }
    return out;
}

} // namespace spdmd::composite::cbor
