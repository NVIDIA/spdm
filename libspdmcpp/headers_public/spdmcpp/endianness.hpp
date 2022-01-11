
#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <limits>

#include <array>
#include <vector>

#include <ostream>

#include <spdmcpp/retstat.hpp>
#include <spdmcpp/enum.hpp>
#include <spdmcpp/flag.hpp>

namespace spdmcpp
{
	///
	/// SPDM packet endianness helpers
	///
	
	//TODO directly specialize basic types and avoid templates
/*	template <typename T>
	inline void endian_swap(T& value)
	{
		uint8_t* p = reinterpret_cast<uint8_t*>(&value);
		for (size_t i = 0; i < sizeof(value) / 2; ++i) {
			std::swap(p[i], p[sizeof(value) - 1 - i]);
		}
	}
	template <typename T>
	inline T endian_read(T value)
	{
		uint8_t* p = reinterpret_cast<uint8_t*>(&value);
		for (size_t i = 0; i < sizeof(value) / 2; ++i) {
			std::swap(p[i], p[sizeof(value) - 1 - i]);
		}
		return value;
	}*/
/*	template <typename T>
	inline void endian_copy(T src, T& dst)
	{
		const uint8_t* psrc = reinterpret_cast<const uint8_t*>(&src);
		uint8_t* pdst = reinterpret_cast<uint8_t*>(&dst);
		for (size_t i = 0; i < sizeof(T); ++i) {
			pdst[i] = psrc[sizeof(T) - 1 - i];
		}
	}*/
	
	inline void endian_copy(uint8_t src, uint8_t& dst)
	{
		dst = src;
	}
	inline void endian_copy(uint16_t src, uint16_t& dst)
	{
		dst = (src >> 8) | (src << 8);
	}
	inline void endian_copy(uint32_t src, uint32_t& dst)
	{
		src = ((src >> 8) & 0x00FF00FF) | ((src << 8) & 0xFF00FF00);
		dst = (src >> 16) | (src << 16);
	}
	
	//TODO proper macro check!!! with override for testing? or just have always swapping functions? and alias/stub for each type?!
	#define SPDMCPP_ENDIAN_SWAP 0
	
#if SPDMCPP_ENDIAN_SWAP
	//big endian
	template <typename T>
	inline void endian_host_spdm_swap(T& value)
	{
		endian_swap(value);
	}
	template <typename T>
	inline T endian_host_spdm_read(T value)
	{
		return endian_read(value);
	}
	template <typename T>
	inline void endian_host_spdm_copy(const T& src, T& dst)
	{
		endian_copy(src, dst);
	}
#else
	//little endian
	template <typename T>
	inline void endian_host_spdm_swap(T& value)
	{
	}
	template <typename T>
	inline T endian_host_spdm_read(T value)
	{
		return value;
	}
	template <typename T>
	inline void endian_host_spdm_copy(const T& src, T& dst)
	{
		dst = src;
	}
#endif
}
