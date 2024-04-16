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




#pragma once
#include <cstdint>
#include <variant>

namespace spdmt
{
    // Get version arguments
    struct VerCmd
    {
        uint8_t ver {0x10};
    };

    // Get capabilities arguments
    struct CapabCmd
    {
        uint32_t flags {0};
        uint8_t ctExponent {0};
    };

    // Negotiate algorithm arguments
    struct NegAlgoCmd
    {
        uint32_t baseAsymAlgo { 0x0000'0080 };
        uint32_t baseHashAlgo { 0x0000'0002 };
    };

    // Cert command arguments
    struct CertCmd
    {
        static constexpr auto wholeChain = -1;
        uint8_t slot {0};
        int offset {wholeChain};
        auto needChain() const {
            return offset==wholeChain;
        }
    };

    // Command measurement arguments
    struct MeasCmd
    {
        uint8_t attributes { 0x01 };
        uint8_t blockIndex { 0xFE };
        uint8_t certSlot { 0x00 };
    };

    // Get digest arguments
    struct DigestCmd
    {
    };

    // Commands container
    using cmdv = std::variant<VerCmd, CapabCmd, NegAlgoCmd, CertCmd, MeasCmd, DigestCmd>;
}