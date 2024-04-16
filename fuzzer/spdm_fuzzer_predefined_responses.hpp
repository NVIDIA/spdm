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

/*
 * Copyright (C) NVIDIA Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <cstdint>
#include <string>
#include <regex>
#include <vector>
#include <map>
#include <filesystem>

namespace fs = std::filesystem;

class PredefinedResponses
{
public:
    PredefinedResponses() = default;

    bool readFromHexFile(const fs::path& path);
    bool readFromLogFile(const fs::path& path);

    const std::vector<uint8_t>& getResponse(uint8_t msgType, int index = 0) const;

    bool containsData() const { return responses.size() > 0; }
    const std::multimap<uint8_t, std::vector<uint8_t>>& getAllResponses() const { return responses; }

private:
    std::vector<uint8_t> readMsgRaw(const std::string &msgStr, size_t pos = 0);

    std::multimap<uint8_t, std::vector<uint8_t>> responses;
    std::vector<uint8_t> empty;
};
