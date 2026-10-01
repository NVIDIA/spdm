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

// Deterministic CBOR encoder.
//
// A thin deterministic wrapper over tinycbor. tinycbor handles the
// encoding (definite-length, shortest-form integers/lengths); this layer
// adds the one rule tinycbor does not enforce: map keys sorted in
// bytewise lexicographic order of their deterministic encodings. All
// composite CBOR — claims-sets, the composite EAT, COSE structures, and
// the tag-602 bundle — flows through this single path so the producer and
// verifier agree on byte-exact output.

#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace spdmd::composite::cbor
{

// --- Primitive appenders ----------------------------------------------------

/// Unsigned integer (major 0).
void putUint(std::vector<std::uint8_t>& out, std::uint64_t v);

/// Signed integer (major 0 when >= 0, major 1 when negative).
void putInt(std::vector<std::uint8_t>& out, std::int64_t v);

/// Byte string (major 2).
void putBytes(std::vector<std::uint8_t>& out, std::span<const std::uint8_t> v);

/// Text string (major 3).
void putText(std::vector<std::uint8_t>& out, std::string_view v);

/// Array header (major 4) — caller appends @p n elements afterward.
void putArrayHeader(std::vector<std::uint8_t>& out, std::size_t n);

/// Map header (major 5) — caller appends @p n key/value pairs afterward.
void putMapHeader(std::vector<std::uint8_t>& out, std::size_t n);

/// Tag (major 6).
void putTag(std::vector<std::uint8_t>& out, std::uint64_t tag);

// --- Value helpers (return a freshly encoded item) --------------------------

std::vector<std::uint8_t> uintVal(std::uint64_t v);
std::vector<std::uint8_t> intVal(std::int64_t v);
std::vector<std::uint8_t> bytesVal(std::span<const std::uint8_t> v);
std::vector<std::uint8_t> textVal(std::string_view v);

/// Encode a definite-length array whose elements are pre-encoded items.
std::vector<std::uint8_t>
    arrayVal(std::span<const std::vector<std::uint8_t>> elems);

// --- Deterministic map builder ----------------------------------------------

/// Collects (key,value) pairs as pre-encoded byte sequences and emits a
/// definite-length map with keys sorted per RFC 8949 §4.2.1.
class Map
{
  public:
    /// Add an entry with an integer key.
    void addInt(std::int64_t key, std::vector<std::uint8_t> value);

    /// Add an entry with a text-string key.
    void addText(std::string_view key, std::vector<std::uint8_t> value);

    /// Number of entries currently held.
    std::size_t size() const
    {
        return entries.size();
    }

    /// Emit the deterministic CBOR map.
    std::vector<std::uint8_t> encode() const;

  private:
    // (encoded-key, encoded-value) pairs.
    std::vector<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>>
        entries;
};

} // namespace spdmd::composite::cbor
