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

#include "../../packet.hpp"

#ifdef SPDMCPP_PACKET_HPP

struct PacketGetCapabilitiesRequest
{
    static constexpr RequestResponseEnum requestResponseCode =
        RequestResponseEnum::REQUEST_GET_CAPABILITIES;
    static constexpr bool sizeIsConstant = true;

    PacketMessageHeader Header = PacketMessageHeader(requestResponseCode);
    uint8_t Reserved0 = 0;
    uint8_t CTExponent = 0;
    uint16_t Reserved1 = 0;
    RequesterCapabilitiesFlags Flags = RequesterCapabilitiesFlags::NIL;

    PacketGetCapabilitiesRequest() = default;
    PacketGetCapabilitiesRequest(uint8_t ctExponent,
                                 RequesterCapabilitiesFlags flags) :
        CTExponent(ctExponent),
        Flags(flags)
    {}

    void printMl(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational) {
            SPDMCPP_LOG_INDENT(log);
            SPDMCPP_LOG_printMl(log, Header);
            SPDMCPP_LOG_iexprln(log, Reserved0);
            SPDMCPP_LOG_iexprln(log, CTExponent);
            SPDMCPP_LOG_iexprln(log, Reserved1);
            SPDMCPP_LOG_iflagsln(log, Flags);
        }
    }
};

inline void endianHostSpdmCopy(const PacketGetCapabilitiesRequest& src,
                               PacketGetCapabilitiesRequest& dst)
{
    endianHostSpdmCopy(src.Header, dst.Header);
    endianHostSpdmCopy(src.Reserved0, dst.Reserved0);
    endianHostSpdmCopy(src.CTExponent, dst.CTExponent);
    endianHostSpdmCopy(src.Reserved1, dst.Reserved1);
    endianHostSpdmCopy(src.Flags, dst.Flags);
}

#endif
