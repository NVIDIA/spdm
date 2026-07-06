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

#pragma once

#include <optional>
#include <string>
#include <variant>

namespace spdmd::dbus_accessors
{

/** @brief Returns the variant's contents if it holds type T, or
 *  std::nullopt otherwise, without throwing on a type mismatch.
 */
template <typename T, typename Variant>
[[nodiscard]] inline std::optional<T> tryGet(const Variant& v)
{
    if (const auto* p = std::get_if<T>(&v))
    {
        return *p;
    }
    return std::nullopt;
}

/** @brief Looks up `key` in `props` and returns tryGet<T> of it, or
 *  std::nullopt if the key is absent.
 */
template <typename T, typename PropertyMap>
[[nodiscard]] inline std::optional<T> tryGetProp(const PropertyMap& props,
                                                 const std::string& key)
{
    auto it = props.find(key);
    if (it == props.end())
    {
        return std::nullopt;
    }
    return tryGet<T>(it->second);
}

} // namespace spdmd::dbus_accessors
