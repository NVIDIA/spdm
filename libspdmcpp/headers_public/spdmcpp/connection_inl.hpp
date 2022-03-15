
#pragma once

namespace spdmcpp
{
template <typename T>
RetStat ConnectionClass::send_request(const T& packet, BufEnum bufidx)
{
    Log.iprint("send_request(");
    Log.print(typeid(packet).name());
    Log.println("):");
    packet.print_ml(Log);

    std::vector<uint8_t>& buf = SendBuffer;
    buf.clear();
    TransportClass::LayerState lay;

    if (Transport)
    {
        Transport->encode_pre(buf, lay);
    }

    auto rs = packet_encode(packet, buf, lay.get_end_offset());
    if (is_error(rs))
    {
        return rs;
    }
    if (T::RequestResponseCode ==
            RequestResponseEnum::REQUEST_GET_MEASUREMENTS ||
        T::RequestResponseCode == RequestResponseEnum::RESPONSE_MEASUREMENTS)
    {
        // assert(bufidx == BufEnum::NUM);
        // size_t off = lay.get_end_offset();
        // HashL1L2.update(&buf[off], buf.size() - off);
    }
    if (bufidx != BufEnum::NUM)
    {
        size_t off = lay.get_end_offset();
        AppendToBuf(bufidx, &buf[off], buf.size() - off);
    }

    if (Transport)
    {
        Transport->encode_post(buf, lay);
    }

    Log.iprint("Context->IO->write() buf.size() = ");
    Log.println(buf.size());
    Log.iprint("buf = ");
    Log.println(buf.data(), buf.size());

    rs = Context->IO->write(buf);
    return rs;
}

template <typename T, typename... Targs>
RetStat ConnectionClass::interpret_response(T& packet, Targs... fargs)
{
    TransportClass::LayerState lay; // TODO double decode
    if (Transport)
    {
        Transport->decode(ResponseBuffer, lay);
    }
    size_t off = lay.get_end_offset();
    auto rs = packet_decode(packet, ResponseBuffer, off, fargs...);
    if (is_error(rs))
    {
        if (rs == RetStat::ERROR_WRONG_REQUEST_RESPONSE_CODE)
        {
            Log.iprint("wrong code is: ");
            Log.println(packet_message_header_get_requestresponsecode(
                &ResponseBuffer[lay.get_end_offset()]));
        }
        return rs;
    }
    Log.iprint("interpret_response(");
    Log.print(typeid(packet).name());
    Log.println("):");
    packet.print_ml(Log);
    return rs;
}

template <typename T>
RetStat ConnectionClass::async_response()
{
    Log.iprint("async_response(");
    Log.print(typeid(T).name());
    Log.println("):");
    assert(WaitingForResponse == RequestResponseEnum::INVALID);
    static_assert(is_response(T::RequestResponseCode));
    WaitingForResponse = T::RequestResponseCode;
    return RetStat::OK;
}

template <typename T, typename R>
RetStat ConnectionClass::send_request_setup_response(const T& request,
                                                     const R& /*response*/,
                                                     BufEnum bufidx,
                                                     timeout_ms_t timeout,
                                                     uint16_t retry)
{
    auto rs = send_request(request, bufidx);
    if (is_error(rs))
    {
        return rs;
    }
    rs = async_response<R>();
    if (is_error(rs))
    {
        return rs;
    }
    if (timeout != TIMEOUT_MS_INFINITE)
    {
        rs = Transport->setup_timeout(timeout);
        if (is_error(rs))
        {
            return rs;
        }
        SendTimeout = timeout;
        SendRetry = retry;
    }
    return rs;
}

} // namespace spdmcpp
