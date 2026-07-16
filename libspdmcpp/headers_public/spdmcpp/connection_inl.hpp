/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
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

#include "config.h"

#include "connection.hpp"

#pragma once

namespace spdmcpp
{
template <typename T>
RetStat ConnectionClass::sendRequest(const T& packet, BufEnum bufidx)
{
    if (Log.logLevel >= spdmcpp::LogClass::Level::Informational)
    {
        Log.iprint("sendRequest(");
        Log.print(typeid(packet).name());
        Log.println("):");
    }
    packet.printMl(Log);

    std::vector<uint8_t>& buf = SendBuffer;
    buf.clear();
    TransportClass::LayerState lay;

    if (transport)
    {
        transport->encodePre(buf, lay);
    }

    auto rs = packetEncode(packet, buf, lay.getEndOffset());
    if (isError(rs))
    {
        return rs;
    }
    if (T::requestResponseCode ==
            RequestResponseEnum::REQUEST_GET_MEASUREMENTS ||
        T::requestResponseCode == RequestResponseEnum::RESPONSE_MEASUREMENTS)
    {
        // SPDMCPP_ASSERT(bufidx == BufEnum::NUM);
        // size_t off = lay.getEndOffset();
        // HashL1L2.update(&buf[off], buf.size() - off);
    }
    if (bufidx != BufEnum::NUM)
    {
        size_t off = lay.getEndOffset();

        if (!stateEnabled && bufidx == BufEnum::A)
        {
            // if stateEnabled is false means last request was a Version
            // request, don't add Version request again
        }
        else
        {
            appendToBuf(bufidx, &buf[off], buf.size() - off);
        }
    }

    if (transport)
    {
        transport->encodePost(buf, lay);
    }
    if (Log.logLevel >= spdmcpp::LogClass::Level::Informational)
    {
        Log.iprint("Context->IO->write() buf.size() = ");
        Log.println(buf.size());
        Log.iprint("buf = ");
        Log.println(buf);
    }
    lastSendTimestamp = std::chrono::system_clock::now();
#ifdef MCTP_IN_KERNEL
    rs = context.getIO()->write(buf);
#else
    rs = context.getIO(sockPath)->write(buf);
#endif
    return rs;
}

template <typename T, typename... Targs>
RetStat ConnectionClass::interpretResponse(T& packet, Targs... fargs)
{
    TransportClass::LayerState lay; // TODO double decode
    if (transport)
    {
        transport->decode(ResponseBuffer, lay);
    }
    size_t off = lay.getEndOffset();
    auto rs = packetDecode(Log, packet, ResponseBuffer, off, fargs...);
    if (isError(rs))
    {
        if (rs == RetStat::ERROR_WRONG_REQUEST_RESPONSE_CODE)
        {
            if (Log.logLevel >= spdmcpp::LogClass::Level::Error)
            {
                Log.iprint("wrong code is: ");
                Log.println(packetMessageHeaderGetRequestresponsecode(
                    ResponseBuffer, lay.getEndOffset()));
            }
        }
        return rs;
    }
    if (Log.logLevel >= spdmcpp::LogClass::Level::Informational)
    {
        Log.iprint("interpretResponse(");
        Log.print(typeid(packet).name());
        Log.println("):");
    }
    packet.printMl(Log);
    return rs;
}

template <typename T>
RetStat ConnectionClass::setupResponseWait(timeout_ms_t timeout, uint16_t retry)
{
    if (Log.logLevel >= spdmcpp::LogClass::Level::Informational)
    {
        Log.iprint("asyncResponse(");
        Log.print(typeid(T).name());
        Log.println("):");
    }
    // SPDMCPP_ASSERT(WaitingForResponse == RequestResponseEnum::INVALID);
    if constexpr (!std::is_same_v<T, void>)
    {
        if (WaitingForResponse != RequestResponseEnum::INVALID)
        {
            return RetStat::ERROR_RESPONSE;
        }
        SPDMCPP_STATIC_ASSERT(isResponse(T::requestResponseCode));
        WaitingForResponse = T::requestResponseCode;
        LastWaitingForResponse = WaitingForResponse;
    }
    if (timeout != timeoutMsInfinite)
    {
        auto rs = transport->setupTimeout(timeout);
        if (isError(rs))
        {
            return rs;
        }

        SendTimeout = timeout;
        SendRetry = retry;
    }
    return RetStat::OK;
}

template <typename R = void, typename T>
RetStat ConnectionClass::sendRequestSetupResponse(const T& request,
                                                  BufEnum bufidx,
                                                  timeout_ms_t timeout,
                                                  uint16_t retry)
{
    auto rs = sendRequest(request, bufidx);
    if (isError(rs) &&
        (rs != RetStat::ERROR_TRANSPORT_BUSY || timeout == timeoutMsInfinite))
    {
        return rs;
    }
    // On ERROR_TRANSPORT_BUSY (with a finite timeout) the TX queue was full;
    // SendBuffer holds the encoded packet. Fall through to arm the timeout so
    // handleTimeoutOrRetry() retransmits without blocking the event loop.
    rs = setupResponseWait<R>(timeout, retry);
    if (isError(rs))
    {
        return rs;
    }
    return rs;
}

} // namespace spdmcpp
