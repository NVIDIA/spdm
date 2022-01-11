
#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <limits>

#include <array>
#include <vector>

#include <iostream>

#include "common.hpp"

namespace spdmcpp
{
	//TODO implement warnings and global (maybe granular?) warning policies!?
	// and/or error policies as well, although those would have to be much more specific I imagine...
	
	class ContextClass
	{
		friend ConnectionClass;	//TODO remove!!!
	public:
		ContextClass();
		
		void register_io(IOClass* io)
		{
			assert(!IO);
			IO = io;
		}
		void unregister_io(IOClass* io)
		{
			assert(IO == io);
			IO = nullptr;
		}
		
		void register_transport(TransportClass* transport)
		{
			assert(!Transport);
			Transport = transport;
		}
		void unregister_transport(TransportClass* transport)
		{
			assert(Transport == transport);
			Transport = nullptr;
		}
		
		const std::vector<MessageVersionEnum>& get_supported_versions() const { return SupportedVersions; }
		
		template<typename T>
		RetStat send_request(const T& packet)
		{
			std::vector<uint8_t> buf;//TODO keep around and reserve reasonably to avoid constant dynamic alloc/deallocs
			TransportClass::LayerState lay;
			
			if (Transport) {
				Transport->encode_pre(buf, lay);
			}
			
			packet_encode(packet, buf, lay.get_end_offset());
			
			if (Transport) {
				Transport->encode_post(buf, lay);
			}
			auto rs = IO->write(buf);
			return rs;
		}
		
		template <typename T>
		RetStat receive_response(T& packet)
		{
			std::vector<uint8_t> buf;//TODO keep around and reserve reasonably to avoid constant dynamic alloc/deallocs
			auto rs = IO->read(buf);
			if (is_error(rs)) {
				return rs;
			}
			TransportClass::LayerState lay;
			if (Transport) {
				Transport->decode(buf, lay);
			}
			return packet_decode(packet, buf, lay.get_end_offset());
		}
		
		template<typename T, typename... Targs>
		RetStat helper_retry(uint32_t retry_times, T func, Targs... fargs)
		{
			RetStat rs;
			do {
				rs = func(fargs...);
				if (rs == RetStat::OK) {
					break;
				}
			} while (retry_times-- != 0);
			return rs;
		}
		
		template<typename T, typename... Targs>
		RetStat helper_retry(T func, Targs... fargs)
		{
			return helper_retry(RetryTimes, func, fargs...);
		}
	protected:
		
		
	private:
		std::vector<MessageVersionEnum> SupportedVersions;
		
		TransportClass* Transport = nullptr;
		IOClass* IO = nullptr;
		uint32_t RetryTimes = 0;
	};
}

