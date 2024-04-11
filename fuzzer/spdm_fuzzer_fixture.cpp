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
#include "spdm_fuzzer_fixture.hpp"

namespace spdm_wrapper
{
RetStat FixtureIOClass::write(const std::vector<uint8_t>& buf,
                timeout_us_t /*timeout*/)
{
    writeQueue.push_back(buf);
    if (logStream.is_open())
    {
        logStream << "TX> ";
        logStream << std::hex << std::setfill('0') << std::setw(2);
        for (auto v : buf)
        {
            logStream << int(v) << " ";
        }
        logStream << std::endl;
    }
    return RetStat::OK;
}
RetStat FixtureIOClass::read(std::vector<uint8_t>& buf,
                timeout_us_t /*timeout*/)
{
    if (readQueue.empty())
    {
        return RetStat::ERROR_UNKNOWN;
    }
    std::swap(buf, readQueue.front());

    if (logStream.is_open())
    {
        logStream << "RX> ";
        logStream << std::hex << std::setfill('0') << std::setw(2);
        for (auto v : buf) {
            logStream << int(v) << " ";
        }
        logStream << std::endl;
    }
    readQueue.pop_front();
    return RetStat::OK;
}
}
