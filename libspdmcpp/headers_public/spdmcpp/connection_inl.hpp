
#pragma once

namespace spdmcpp
{
	template<typename T>
	RetStat ConnectionClass::send_request(const T& packet, BufEnum bufidx)
	{
		Log.iprint("send_request(");
		Log.print(typeid(packet).name());
		Log.println("):");
		packet.print_ml(Log);
		
	//	return Context->send_request(packet);
		std::vector<uint8_t> buf;//TODO keep around and reserve reasonably to avoid constant dynamic alloc/deallocs
		TransportClass::LayerState lay;
		
		if (Context->Transport) {
			Context->Transport->encode_pre(buf, lay);
		}
		
		packet_encode(packet, buf, lay.get_end_offset());
		if (T::RequestResponseCode == RequestResponseEnum::REQUEST_GET_MEASUREMENTS || T::RequestResponseCode == RequestResponseEnum::RESPONSE_MEASUREMENTS) {
			assert(bufidx == BufEnum::NUM);
			size_t off = lay.get_end_offset();
			HashL1L2.update(&buf[off], buf.size() - off);
		}
		if (bufidx != BufEnum::NUM) {
			size_t off = lay.get_end_offset();
			AppendToBuf(bufidx, &buf[off], buf.size() - off);
		}
		
		if (Context->Transport) {
			Context->Transport->encode_post(buf, lay);
		}
		
		Log.iprint("Context->IO->write() buf.size() = ");
		Log.println(buf.size());
		Log.iprint("buf = ");
		Log.println(buf.data(), buf.size());
		
		auto rs = Context->IO->write(buf);
		return rs;
	}
	
	template <typename T>
	RetStat ConnectionClass::receive_response(T& packet)
	{
	//	auto rs = Context->receive_response(packet);
		ResponseBuffer.clear();
		auto rs = Context->IO->read(ResponseBuffer);
		if (is_error(rs)) {
			return rs;
		}
		return interpret_response(packet);
	}
	
	template <typename T, typename... Targs>
	RetStat ConnectionClass::interpret_response(T& packet, Targs... fargs)
	{
		TransportClass::LayerState lay;//TODO double decode
		if (Context->Transport) {
			Context->Transport->decode(ResponseBuffer, lay);
		}
		auto rs = packet_decode(packet, ResponseBuffer, lay.get_end_offset(), fargs...);
		if (is_error(rs)) {
			if (rs == RetStat::ERROR_WRONG_REQUEST_RESPONSE_CODE) {
				Log.iprint("wrong code is: ");
				Log.println(packet_message_header_get_requestresponsecode(&ResponseBuffer[lay.get_end_offset()]));
			}
			return rs;
		}
		Log.iprint("interpret_response(");
		Log.print(typeid(packet).name());
		Log.println("):");
		packet.print_ml(Log);
		return rs;
	}
	
	template<typename T>
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
	
	template<typename T, typename R>
	RetStat ConnectionClass::send_request_setup_response(const T& request, const R& /*response*/, BufEnum bufidx)
	{
		auto rs = send_request(request, bufidx);
		if (is_error(rs)) {
			return rs;
		}
		async_response<R>();
		return rs;
	}
	
}

