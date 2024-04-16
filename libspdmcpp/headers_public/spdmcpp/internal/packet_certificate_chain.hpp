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
#include <vector>
#include <cstdint>

#include "../packet.hpp"
#include "../enum_defs.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct PacketCertificateChain
{
    uint16_t Length = 0;
    uint16_t Reserved = 0;

    static constexpr bool sizeIsConstant = true;

    void print(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational) {
            log.print("<");
            SPDMCPP_LOG_expr(log, Length);
            log.print("   ");
            SPDMCPP_LOG_expr(log, Reserved);
            log.print("   ");
            log.print(">");
        }
    }
};

inline void endianHostSpdmCopy(const PacketCertificateChain& src,
                               PacketCertificateChain& dst)
{
    endianHostSpdmCopy(src.Length, dst.Length);
    endianHostSpdmCopy(src.Reserved, dst.Reserved);
}

#endif
