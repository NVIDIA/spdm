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




#include <list>
#include <vector>

#include <spdmcpp/assert.hpp>
#include <spdmcpp/common.hpp>
#include <spdmcpp/connection.hpp>
#include <spdmcpp/context.hpp>
#include <spdmcpp/mbedtls_support.hpp>
#include <spdmcpp/mctp_support.hpp>

#include <libspdmcpp/headers/spdmcpp/helpers.hpp>
#include <fstream>
#include <string>

using namespace spdmcpp;

namespace spdm_wrapper
{

class FixtureTransportClass : public MctpTransportClass
{
  public:
    FixtureTransportClass() = delete;
    explicit FixtureTransportClass(int eid) : MctpTransportClass(eid) {}

    spdmcpp::RetStat setupTimeout(spdmcpp::timeout_us_t /*timeout*/) override
    {
        return spdmcpp::RetStat::OK;
    }
};

class FixtureIOClass : public spdmcpp::IOClass
{
  public:
    FixtureIOClass() = delete;

    //NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    FixtureIOClass(std::string_view logName, std::list<std::vector<uint8_t>> &readQueue, std::list<std::vector<uint8_t>> &writeQueue):
      readQueue(readQueue), writeQueue(writeQueue)
    {
        if (!logName.empty())
        {
            logStream.open(std::string(logName).c_str(), std::ios::app);
        }
    }

    RetStat write(const std::vector<uint8_t>& buf,
                  timeout_us_t /*timeout*/ = timeoutUsInfinite) override;

    RetStat read(std::vector<uint8_t>& buf,
                 timeout_us_t /*timeout*/ = timeoutUsInfinite) override;

    void clearTx() { writeQueue.clear(); }

  private:
    std::list<std::vector<uint8_t>> &readQueue;
    std::list<std::vector<uint8_t>> &writeQueue;
    std::ofstream logStream;
};

}
