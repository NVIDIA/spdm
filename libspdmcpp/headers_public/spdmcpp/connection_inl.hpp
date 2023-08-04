
#include "connection.hpp"

#pragma once

namespace spdmcpp
{
template <typename T>
RetStat ConnectionClass::sendRequest(const T& packet, BufEnum bufidx)
{
    if (Log.logLevel >= spdmcpp::LogClass::Level::Informational) {
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
        appendToBuf(bufidx, &buf[off], buf.size() - off);
    }

    if (transport)
    {
        transport->encodePost(buf, lay);
    }
    if (Log.logLevel >= spdmcpp::LogClass::Level::Informational) {
        Log.iprint("Context->IO->write() buf.size() = ");
        Log.println(buf.size());
        Log.iprint("buf = ");
        Log.println(buf);
    }

    rs = context.getIO(currentMedium).write(buf);
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
            if (Log.logLevel >= spdmcpp::LogClass::Level::Error) {
                Log.iprint("wrong code is: ");
                Log.println(packetMessageHeaderGetRequestresponsecode(
                    ResponseBuffer, lay.getEndOffset()));
            }
        }
        return rs;
    }
    if (Log.logLevel >= spdmcpp::LogClass::Level::Informational) {
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
    if (Log.logLevel >= spdmcpp::LogClass::Level::Informational) {
        Log.iprint("asyncResponse(");
        Log.print(typeid(T).name());
        Log.println("):");
    }
    //SPDMCPP_ASSERT(WaitingForResponse == RequestResponseEnum::INVALID);
    if(WaitingForResponse != RequestResponseEnum::INVALID) {
        return RetStat::ERROR_RESPONSE;
    }
    SPDMCPP_STATIC_ASSERT(isResponse(T::requestResponseCode));
    WaitingForResponse = T::requestResponseCode;
    LastWaitingForResponse = WaitingForResponse;

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

template <typename R, typename T>
RetStat ConnectionClass::sendRequestSetupResponse(const T& request,
                                                  BufEnum bufidx,
                                                  timeout_ms_t timeout,
                                                  uint16_t retry)
{
    auto rs = sendRequest(request, bufidx);
    if (isError(rs))
    {
        return rs;
    }
    rs = setupResponseWait<R>(timeout, retry);
    if (isError(rs))
    {
        return rs;
    }
    return rs;
}

} // namespace spdmcpp
