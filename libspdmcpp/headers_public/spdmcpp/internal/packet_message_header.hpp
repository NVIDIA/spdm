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

#include "../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

struct PacketMessageHeader
{
    MessageVersionEnum MessageVersion = MessageVersionEnum::SPDM_1_0;
    RequestResponseEnum requestResponseCode = RequestResponseEnum::INVALID;
    uint8_t Param1 = 0;
    uint8_t Param2 = 0;

    static constexpr bool sizeIsConstant = true;

    PacketMessageHeader() = default;
    explicit PacketMessageHeader(RequestResponseEnum rr) :
        requestResponseCode(rr)
    {}
    explicit PacketMessageHeader(MessageVersionEnum v, RequestResponseEnum rr) :
        MessageVersion(v), requestResponseCode(rr)
    {}

    void print(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational) {
            log.print('<');
            SPDMCPP_LOG_expr(log, MessageVersion);
            log.print("   ");
            SPDMCPP_LOG_expr(log, requestResponseCode);
            log.print("   ");
            SPDMCPP_LOG_expr(log, Param1);
            log.print("   ");
            SPDMCPP_LOG_expr(log, Param2);
            log.print(">");
        }
    }
    void printMl(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational) {
            SPDMCPP_LOG_INDENT(log);
            SPDMCPP_LOG_iexprln(log, MessageVersion);
            SPDMCPP_LOG_iexprln(log, requestResponseCode);
            SPDMCPP_LOG_iexprln(log, Param1);
            SPDMCPP_LOG_iexprln(log, Param2);
        }
    }
};

[[nodiscard]] inline MessageVersionEnum
    packetMessageHeaderGetMessageVersion(const std::vector<uint8_t>& buf,
                                         size_t off = 0)
{
    return static_cast<MessageVersionEnum>(
        buf[off + offsetof(PacketMessageHeader, MessageVersion)]);
}

[[nodiscard]] inline RequestResponseEnum
    packetMessageHeaderGetRequestresponsecode(const std::vector<uint8_t>& buf,
                                              size_t off = 0)
{
    return static_cast<RequestResponseEnum>(
        buf[off + offsetof(PacketMessageHeader, requestResponseCode)]);
}
inline void
    packetMessageHeaderSetRequestresponsecode(uint8_t* buf,
                                              RequestResponseEnum rrcode)
{
    // NOLINTNEXTLINE cppcoreguidelines-pro-type-reinterpret-cast
    auto& p = *reinterpret_cast<PacketMessageHeader*>(buf);
    SPDMCPP_STATIC_ASSERT(sizeof(p.requestResponseCode) == 1);
    p.requestResponseCode = rrcode;
}

inline void endianHostSpdmCopy(const PacketMessageHeader& src,
                               PacketMessageHeader& dst)
{
    endianHostSpdmCopy(src.MessageVersion, dst.MessageVersion);
    endianHostSpdmCopy(src.requestResponseCode, dst.requestResponseCode);
    endianHostSpdmCopy(src.Param1, dst.Param1);
    endianHostSpdmCopy(src.Param2, dst.Param2);
}

#endif
