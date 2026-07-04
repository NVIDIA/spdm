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

// PEM -> DER helper for composite attestation. Concatenates the DER of
// every certificate in a PEM chain (leaf-first order preserved), used to
// turn a Responder's PEM chain into the raw SPDM cert_chain bytes for a
// detached Claims-Set.

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

namespace spdmd::composite
{

std::vector<std::uint8_t> pemToDerConcat(std::string_view pem);

} // namespace spdmd::composite
