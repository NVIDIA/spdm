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

struct PacketVersionNumber
{
    uint16_t Bits = 0;

    static constexpr bool sizeIsConstant = true;

    uint8_t getMajor() const
    {
        return Bits >> 12 & 0xF;
    }
    uint8_t getMinor() const
    {
        return Bits >> 8 & 0xF;
    }
    uint8_t setMinor() const
    {
        return Bits >> 8 & 0xF;
    }
    uint8_t getUpdateVersionNumber() const
    {
        return Bits >> 4 & 0xF;
    }
    uint8_t getAlpha() const
    {
        return Bits & 0xF;
    }

    void setMajor(uint8_t value)
    {
        Bits &= ~(0xF << 12);
        Bits |= value << 12;
    }
    void setMinor(uint8_t value)
    {
        Bits &= ~(0xF << 8);
        Bits |= value << 8;
    }

    MessageVersionEnum getMessageVersion() const
    {
        switch (getMajor())
        {
            case 1:
                switch (getMinor())
                {
                    case 0:
                        return MessageVersionEnum::SPDM_1_0;
                    case 1:
                        return MessageVersionEnum::SPDM_1_1;
                }
        }
        return MessageVersionEnum::UNKNOWN;
    }

    void print(LogClass& log) const
    {
        if (log.logLevel >= LogClass::Level::Informational) {
            log.print("<");
            SPDMCPP_LOG_expr(log, getMajor());
            log.print("   ");
            SPDMCPP_LOG_expr(log, getMinor());
            log.print("   ");
            SPDMCPP_LOG_expr(log, getUpdateVersionNumber());
            log.print("   ");
            SPDMCPP_LOG_expr(log, getAlpha());
            log.print(">");
        }
    }

    bool operator==(const PacketVersionNumber& other) const
    {
        return Bits == other.Bits;
    }
};

inline void endianHostSpdmCopy(const PacketVersionNumber& src,
                               PacketVersionNumber& dst)
{
    endianHostSpdmCopy(src.Bits, dst.Bits);
}

#endif
