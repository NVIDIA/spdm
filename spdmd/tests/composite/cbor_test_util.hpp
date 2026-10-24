/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION &
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

// Test-side CBOR decoder, built on tinycbor. Decodes the deterministic
// subset emitted by spdmd::composite::cbor into an inspectable tree.
// Tests rely on the vetted tinycbor parser rather than a hand-rolled one.

#pragma once

#include <cbor.h>

#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace cbortest
{

struct Item;
using ItemPtr = std::shared_ptr<Item>;

struct Item
{
    int major = -1;         // CBOR major type 0..7
    std::uint64_t uarg = 0; // uint value / len
    std::int64_t ival = 0;  // signed value for major 0/1
    std::vector<std::uint8_t> bytes;
    std::string text;
    std::vector<ItemPtr> array;
    std::vector<std::pair<ItemPtr, ItemPtr>> map;
    std::uint64_t tag = 0; // major 6
    ItemPtr tagged;        // content of a tag

    bool isUint() const
    {
        return major == 0;
    }
    bool isInt() const
    {
        return major == 0 || major == 1;
    }
    bool isBytes() const
    {
        return major == 2;
    }
    bool isText() const
    {
        return major == 3;
    }
    bool isArray() const
    {
        return major == 4;
    }
    bool isMap() const
    {
        return major == 5;
    }
    bool isTag() const
    {
        return major == 6;
    }

    ItemPtr atInt(std::int64_t key) const
    {
        for (const auto& [k, v] : map)
        {
            if (k->isInt() && k->ival == key)
            {
                return v;
            }
        }
        return nullptr;
    }

    ItemPtr atText(const std::string& key) const
    {
        for (const auto& [k, v] : map)
        {
            if (k->isText() && k->text == key)
            {
                return v;
            }
        }
        return nullptr;
    }
};

inline ItemPtr decodeValue(CborValue* it)
{
    auto item = std::make_shared<Item>();
    const CborType t = cbor_value_get_type(it);
    switch (t)
    {
        case CborIntegerType:
        {
            item->major = cbor_value_is_negative_integer(it) ? 1 : 0;
            std::int64_t v = 0;
            cbor_value_get_int64(it, &v);
            item->ival = v;
            item->uarg = static_cast<std::uint64_t>(v);
            cbor_value_advance_fixed(it);
            break;
        }
        case CborByteStringType:
        {
            item->major = 2;
            std::size_t n = 0;
            cbor_value_get_string_length(it, &n);
            item->bytes.resize(n);
            std::uint8_t one = 0;
            std::uint8_t* p = n ? item->bytes.data() : &one;
            std::size_t cap = n ? n : 1;
            cbor_value_copy_byte_string(it, p, &cap, it);
            break;
        }
        case CborTextStringType:
        {
            item->major = 3;
            std::size_t n = 0;
            cbor_value_get_string_length(it, &n);
            std::vector<char> buf(n + 1);
            std::size_t cap = buf.size();
            cbor_value_copy_text_string(it, buf.data(), &cap, it);
            item->text.assign(buf.data(), cap);
            break;
        }
        case CborArrayType:
        {
            item->major = 4;
            CborValue rec;
            cbor_value_enter_container(it, &rec);
            while (!cbor_value_at_end(&rec))
            {
                item->array.push_back(decodeValue(&rec));
            }
            cbor_value_leave_container(it, &rec);
            break;
        }
        case CborMapType:
        {
            item->major = 5;
            CborValue rec;
            cbor_value_enter_container(it, &rec);
            while (!cbor_value_at_end(&rec))
            {
                ItemPtr k = decodeValue(&rec);
                ItemPtr v = decodeValue(&rec);
                item->map.emplace_back(std::move(k), std::move(v));
            }
            cbor_value_leave_container(it, &rec);
            break;
        }
        case CborTagType:
        {
            item->major = 6;
            CborTag tg = 0;
            cbor_value_get_tag(it, &tg);
            item->tag = tg;
            cbor_value_advance_fixed(it);
            item->tagged = decodeValue(it);
            break;
        }
        default:
            throw std::runtime_error("cbortest: unsupported type");
    }
    return item;
}

inline ItemPtr decode(std::span<const std::uint8_t> b)
{
    CborParser parser;
    CborValue it;
    if (cbor_parser_init(b.data(), b.size(), 0, &parser, &it) != CborNoError)
    {
        throw std::runtime_error("cbortest: parser init failed");
    }
    return decodeValue(&it);
}

} // namespace cbortest
