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

// MockAttester — software-only PlatformAttester backend.
//
// Development backend (attester-backend=mock). Acts as a stand-in Lead
// Attester / RoT: it owns a mock eat_profile,
// a mock ueid, and a mock measurements set, generates an ephemeral
// ECDSA-P384 key + self-signed leaf at construction, and produces
// verifier-compatible CWT(COSE_Sign1) composite EAT tokens in userspace.
//
// Its status is always SoftwareMock when initialized.

#pragma once

#include "platform_attester.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string>

namespace spdmd::mock_attester
{

struct MockAttesterConfig
{
    /// Composite EAT profile URI the mock RoT writes into eat_profile
    /// (265). The Lead Attester owns this — the BMC never supplies it.
    std::string profileUri =
        "tag:example,2026:platform-composite-attestation-v1";

    /// Common Name placed in the self-signed mock leaf certificate.
    std::string leafCn = "PlatformAttesterMock";
};

class MockAttester : public PlatformAttester
{
  public:
    explicit MockAttester(MockAttesterConfig cfg = {});
    ~MockAttester() override;

    MockAttester(const MockAttester&) = delete;
    MockAttester& operator=(const MockAttester&) = delete;
    MockAttester(MockAttester&&) noexcept;
    MockAttester& operator=(MockAttester&&) noexcept;

    composite::CompositeEatResponse generateCompositeEat(
        const composite::CompositeEatRequest& req) override;

    PlatformAttesterStatus getStatus() const override;

    /// Test hook: PEM cert chain that signs the composite token.
    const std::string& getCertChainPEM() const;

    /// Test hook: the mock Lead Attester ueid bytes (16 bytes).
    std::span<const std::uint8_t> getUeid() const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace spdmd::mock_attester
