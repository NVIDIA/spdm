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

#include "libspdmcpp/headers_public/spdmcpp/flag.hpp"

#include "spdm_fuzzer_config.hpp"
#include "spdm_fuzzer_predefined_responses.hpp"

namespace spdm_wrapper
{
class SpdmWrapperApp
{
  public:
    void setupCli(int argc, char** argv);
    bool run(spdmcpp::BaseAsymAlgoFlags asymAlgo, spdmcpp::BaseHashAlgoFlags hashAlgo);

  private:
    WrapperConfig config;
    PredefinedResponses predefinedResponses;

    //spdmcpp::LogClass::Level verbose = spdmcpp::LogClass::Level::Emergency;
};

} // namespace spdm_wrapper
