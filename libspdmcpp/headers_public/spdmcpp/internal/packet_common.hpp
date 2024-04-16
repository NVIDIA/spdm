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





#include "../packet.hpp"

#pragma once

#ifdef SPDMCPP_PACKET_HPP

// helper for basic types
template <typename T>
[[nodiscard]] RetStat packetDecodeBasic(spdmcpp::LogClass& logg, T& p, const std::vector<uint8_t>& buf,
                                        size_t& start)
{
    if (start >= buf.size())
    {
        SPDMCPP_LOG_TRACE(logg, start);
        SPDMCPP_LOG_TRACE(logg, buf.size());
        return RetStat::ERROR_BUFFER_TOO_SMALL;
    }
    if (start + sizeof(p) > buf.size())
    {
        SPDMCPP_LOG_TRACE(logg, start);
        SPDMCPP_LOG_TRACE(logg, sizeof(p));
        SPDMCPP_LOG_TRACE(logg, buf.size());
        return RetStat::ERROR_BUFFER_TOO_SMALL;
    }
    // NOLINTNEXTLINE cppcoreguidelines-pro-type-reinterpret-cast
    endianHostSpdmCopy(*reinterpret_cast<const T*>(&buf[start]), p);
    start += sizeof(T);
    return RetStat::OK;
}

// helper for statically sized structures
template <typename T>
[[nodiscard]] RetStat
    packetDecodeInternal(spdmcpp::LogClass& logg ,T& p, const std::vector<uint8_t>& buf, size_t& start)
{
    SPDMCPP_STATIC_ASSERT(T::sizeIsConstant);

    if (start >= buf.size())
    {
        SPDMCPP_LOG_TRACE(logg, start);
        SPDMCPP_LOG_TRACE(logg, buf.size());
        return RetStat::ERROR_BUFFER_TOO_SMALL;
    }
    if (start + sizeof(p) > buf.size())
    {
        SPDMCPP_LOG_TRACE(logg, start);
        SPDMCPP_LOG_TRACE(logg, sizeof(p));
        SPDMCPP_LOG_TRACE(logg, buf.size());
        return RetStat::ERROR_BUFFER_TOO_SMALL;
    }
    // NOLINTNEXTLINE cppcoreguidelines-pro-type-reinterpret-cast
    endianHostSpdmCopy(*reinterpret_cast<const T*>(&buf[start]), p);
    start += sizeof(T);
    return RetStat::OK;
}

/** @brief The top function for decoding SPDM packets
 *  @param[out] p - The packet to decode into, if the decoded packet type does
 * not match decoding is stopped and RetStat::ERROR_WRONG_REQUEST_RESPONSE_CODE
 * is returned
 *  @param[in] buf - The buffer from which to decode the packet
 *  @param[inout] off - An offset into the buffer at which to start decoding,
 * the value shall be increased as the packet is being decoded such that at the
 * end it marks the offset right after the decoded packet
 */
template <typename T, typename... Targs>
[[nodiscard]] RetStat packetDecode(spdmcpp::LogClass& logg,T& p, const std::vector<uint8_t>& buf,
                                   size_t& off, Targs... fargs)
{
    if (off + sizeof(PacketMessageHeader) > buf.size())
    {
        SPDMCPP_LOG_TRACE(logg, off);
        SPDMCPP_LOG_TRACE(logg,  sizeof(PacketMessageHeader));
        SPDMCPP_LOG_TRACE(logg, buf.size());
        return RetStat::ERROR_BUFFER_TOO_SMALL;
    }
    if (packetMessageHeaderGetRequestresponsecode(buf, off) !=
        T::requestResponseCode)
    {
        SPDMCPP_LOG_TRACE(logg, off);
        SPDMCPP_LOG_TRACE(logg,  sizeof(PacketMessageHeader));
        SPDMCPP_LOG_TRACE(logg, buf.size());
        return RetStat::ERROR_WRONG_REQUEST_RESPONSE_CODE;
    }
    auto rs = packetDecodeInternal(logg, p, buf, off, fargs...);
    if (isError(rs))
    {
        SPDMCPP_LOG_TRACE(logg, off);
        SPDMCPP_LOG_TRACE(logg,  sizeof(PacketMessageHeader));
        SPDMCPP_LOG_TRACE(logg, buf.size());
        return rs;
    }
    if (off < buf.size())
    {
        return RetStat::WARNING_BUFFER_TOO_BIG;
    }
    return rs;
}

template <typename T>
void packetEncodeBasic(const T& p, uint8_t* buf)
{
    // NOLINTNEXTLINE cppcoreguidelines-pro-type-reinterpret-cast
    endianHostSpdmCopy(p, *reinterpret_cast<T*>(buf));
}
template <typename T>
void packetEncodeBasic(const T& p, std::vector<uint8_t>& buf, size_t& start)
{
    SPDMCPP_STATIC_ASSERT(std::is_integral<T>::value || std::is_enum<T>::value);
    if (buf.size() < start + sizeof(p))
    {
        buf.resize(start + sizeof(p));
    }
    packetEncodeBasic(p, &buf[start]);
    start += sizeof(T);
}
template <typename T>
[[nodiscard]] RetStat
    packetEncodeInternal(const T& p, std::vector<uint8_t>& buf, size_t& start)
{
    SPDMCPP_STATIC_ASSERT(T::sizeIsConstant);
    if (buf.size() < start + sizeof(p))
    {
        buf.resize(start + sizeof(p));
    }
    packetEncodeBasic(p, &buf[start]);
    start += sizeof(T);
    return RetStat::OK;
}

/** @brief The top function for encoding SPDM packets
 *  @param[in] p - The packet to encode
 *  @param[out] buf - The buffer to write the data into, will be resized if
 * necessary
 *  @param[in] start - An offset at which to write into the buffer, typically
 * used
 */
template <typename T>
[[nodiscard]] RetStat packetEncode(const T& p, std::vector<uint8_t>& buf,
                                   size_t start = 0)
{
    // TODO maybe we should require a finalize() function and always do
    // p.finalize() here for safety?
    auto rs = packetEncodeInternal(p, buf, start);
    if (isError(rs))
    {
        return rs;
    }
    if (start + sizeof(p) < buf.size())
    {
        return RetStat::WARNING_BUFFER_TOO_BIG;
    }
    return rs;
}

// helpers for simple byte chunks
inline void packetEncodeBasic(const uint8_t* src, size_t size,
                              std::vector<uint8_t>& buf, size_t& start)
{
    if (buf.size() < start + size)
    {
        buf.resize(start + size);
    }
    if(!src)
    {
        return;
    }
    memcpy(&buf[start], src, size);
    start += size;
}
inline void packetEncodeBasic(const std::vector<uint8_t>& src,
                              std::vector<uint8_t>& buf, size_t& start)
{
    packetEncodeBasic(src.data(), src.size(), buf, start);
}

template <size_t N>
inline void packetEncodeBasic(const std::array<uint8_t, N>& src,
                              std::vector<uint8_t>& buf, size_t& start)
{
    packetEncodeBasic(src.data(), src.size(), buf, start);
}

[[nodiscard]] inline RetStat packetDecodeBasic(spdmcpp::LogClass& logg,uint8_t* dst, size_t size,
                                               const std::vector<uint8_t>& buf,
                                               size_t& start)
{
    if (start + size > buf.size())
    {
        SPDMCPP_LOG_TRACE(logg,start);
        SPDMCPP_LOG_TRACE(logg,size);
        SPDMCPP_LOG_TRACE(logg,buf.size());
        return RetStat::ERROR_BUFFER_TOO_SMALL;
    }
    if (dst)
    {
        memcpy(dst, &buf[start], size);
    }
    start += size;
    return RetStat::OK;
}
[[nodiscard]] inline RetStat packetDecodeBasic(spdmcpp::LogClass& logg,std::vector<uint8_t>& dst,
                                               const std::vector<uint8_t>& buf,
                                               size_t& start)
{
    return packetDecodeBasic(logg, dst.data(), dst.size(), buf, start);
}

#endif
