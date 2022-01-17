
#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>
#include <limits>
#include <random>

// #include <array>
#include <vector>

namespace spdmcpp
{
	constexpr std::mt19937::result_type mt19937_default_seed = 13;
	
	inline void fill_pseudorandom(std::vector<uint8_t>& buf, std::mt19937::result_type seed = mt19937_default_seed)
	{
		std::mt19937 gen(seed);
		std::uniform_int_distribution<uint8_t> distrib(1);//avoid 0
		for (size_t i = 0; i < buf.size(); ++i) {
			buf[i] = distrib(gen);
		}
	}
	template <size_t N>
	void fill_pseudorandom(uint8_t (&buf)[N], std::mt19937::result_type seed = mt19937_default_seed)
	{
#if 1
		std::mt19937 gen(seed);
		std::uniform_int_distribution<uint8_t> distrib(1);
		for (size_t i = 0; i < N; ++i) {
			buf[i] = distrib(gen);
		}
#else
		for (size_t i = 0; i < N; ++i) {
			buf[i] = i + 1;
		}
#endif
	}
	
	template <typename T>
	inline void fill_pseudorandom_type(T& dst, std::mt19937::result_type seed = mt19937_default_seed)
	{
		uint8_t* buf = reinterpret_cast<uint8_t*>(&dst);
		std::mt19937 gen(seed);
		std::uniform_int_distribution<uint8_t> distrib(0);
		for (size_t i = 0; i < sizeof(T); ++i) {
			buf[i] = distrib(gen);
		}
	}
	template <typename T>
	inline T return_pseudorandom_type(std::mt19937::result_type seed = mt19937_default_seed)
	{
		T dst;
		fill_pseudorandom_type(dst, seed);
		return dst;
	}



	inline void fill_random(std::vector<uint8_t>& buf)
	{
#if 0
		std::random_device rd;
		std::default_random_engine gen(rd());
		std::uniform_int_distribution<uint8_t> distrib(0);
		for (size_t i = 0; i < buf.size(); ++i) {
			buf[i] = distrib(gen);
		}
#else
		for (size_t i = 0; i < buf.size(); ++i) {
			buf[i] = i + 1;
		}
#endif
	}
	
/*	template <size_t N>
	void fill_random(std::array<uint8_t, N>& buf)
	{
		std::random_device rd;
		std::default_random_engine gen(rd());
		std::uniform_int_distribution<uint8_t> distrib(0);
		for (size_t i = 0; i < buf.size(); ++i) {
			buf[i] = distrib(gen);
		}
	}*/

	template <size_t N>
	void fill_random(uint8_t (&buf)[N])
	{
#if 1
		std::random_device rd;
		std::default_random_engine gen(rd());
		std::uniform_int_distribution<uint8_t> distrib(0);
		for (size_t i = 0; i < N; ++i) {
			buf[i] = distrib(gen);
		}
#else
		for (size_t i = 0; i < N; ++i) {
			buf[i] = i + 1;
		}
#endif
	}
}
