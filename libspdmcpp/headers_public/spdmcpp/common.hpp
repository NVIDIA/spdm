
#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <limits>

#include <array>
#include <vector>

#include <iostream>

#include "retstat.hpp"
#include "log.hpp"
#include "packet.hpp"

namespace spdmcpp
{
	//TODO implement warnings and global (maybe granular?) warning policies!?
	// and/or error policies as well, although those would have to be much more specific I imagine...
	
	
	typedef uint64_t timeout_us_t;	///in units of 1 micro second
	enum : timeout_us_t {
		TIMEOUT_US_INFINITE = std::numeric_limits<timeout_us_t>::max()
	};
	
	
	class ConnectionClass;
	class ContextClass;
	
	class TransportClass	//TODO almost for sure will require custom data per-connection, also how to handle encrypted sessions?!
	{
	public:
		class LayerState
		{
			friend TransportClass;
		public:
			size_t get_offset() const			{ return Offset; }
			size_t get_end_offset() const		{ return Offset + Size; }
		protected:
			size_t Offset = 0;
			size_t Size = 0;
			void* Priv = nullptr;
		};
		
		virtual ~TransportClass()
		{
		}
		
		virtual RetStat encode_pre(std::vector<uint8_t>& buf, LayerState& lay) = 0;
		virtual RetStat encode_post(std::vector<uint8_t>& buf, LayerState& lay) = 0;
		
		virtual RetStat decode(std::vector<uint8_t>& buf, LayerState& lay) = 0;
	protected:
		
		template <class T> T& get_header_ref(std::vector<uint8_t>& buf, LayerState& lay)	{ return *reinterpret_cast<T*>(&buf[lay.get_offset()]); }
		
		void set_layer_offset(LayerState& lay, size_t v)	{ lay.Offset = v; }
		void set_layer_size(LayerState& lay, size_t v)		{ lay.Size = v; }
		void set_layer_priv(LayerState& lay, void* v)		{ lay.Priv = v; }
		
	};

	class IOClass
	{
	public:
		virtual ~IOClass() {};
		virtual RetStat write(const std::vector<uint8_t>& buf, timeout_us_t timeout = TIMEOUT_US_INFINITE) = 0;
		virtual RetStat read(std::vector<uint8_t>& buf, timeout_us_t timeout = TIMEOUT_US_INFINITE) = 0;
		virtual RetStat setup_timeout(timeout_us_t timeout = TIMEOUT_US_INFINITE) = 0;
	};
	
	
}


#include "context.hpp"
#include "connection.hpp"
