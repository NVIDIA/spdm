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
#include <spdmcpp/common.hpp>
#include <spdmcpp/connection.hpp>

#include "spdm_fuzzer_config.hpp"

using namespace spdmcpp;

namespace spdm_wrapper
{
class Requester
{
  public:
    Requester(IOClass &io, ConnectionClass &connection): io(io), connection(connection) {}

    RetStat startRefreshFlow();
    RetStat handleRecv();
    inline RequestResponseEnum getExpectedResponse() { return connection.getWaitingForResponse();}

  private:
    IOClass         &io;
    ConnectionClass &connection;
};
} //spdm_wrapper
