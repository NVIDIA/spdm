
#include <array>
#include <cstring>
#include <vector>
#include <random>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <spdmcpp/packet.hpp>

#include <spdmcpp/helpers.hpp>

using namespace spdmcpp;

#define SPDMCPP_TEST_ASSERT_RS(rs,val) do {			\
		if ((rs) != (val)) {			\
			std::cerr << "Unexpected: " #rs " = " << get_cstr(rs) << std::endl;			\
			std::cerr << " in: " << __func__ << "() @ " << __FILE__ << " : " << std::dec << __LINE__ << std::endl;			\
			return false;			\
		}			\
	} while(false)

void print(const std::vector<uint8_t>& buf)
{
	for (size_t i = 0; i < buf.size(); ++i) {
		if (i)
			std::cerr << " 0x";
		else
			std::cerr << "0x";
		std::cerr << std::hex << (int)buf[i];
	}
}

template <typename T>
inline void fill_pseudorandom_packet(T& p, std::mt19937::result_type seed = mt19937_default_seed)
{
	static_assert(T::size_is_constant);
	fill_pseudorandom_type(p, seed);
	packet_message_header_set_requestresponsecode(reinterpret_cast<uint8_t*>(&p), T::RequestResponseCode);
}

template <typename T>
inline T return_pseudorandom_packet(std::mt19937::result_type seed = mt19937_default_seed)
{
	T p;
	fill_pseudorandom_packet(p, seed);
	return p;
}



template <class T>
bool packet_pseudorandom_decode_encode_basic()
{
	static_assert(T::size_is_constant);
	std::vector<uint8_t> src, dst;
	src.resize(sizeof(T));
	fill_pseudorandom(src);
	std::cerr << "src: ";
	print(src);
	std::cerr << std::endl;
	
	T packet;
	{
		size_t off = 0;
		auto rs = packet_decode_basic(packet, src, off);
		SPDMCPP_TEST_ASSERT_RS(rs, RetStat::OK);
		if (off != src.size()) {
			std::cerr << "off: " << off << std::endl;
			return false;
		}
	}
	{
		auto rs = packet_encode(packet, dst);
		SPDMCPP_TEST_ASSERT_RS(rs, RetStat::OK);
	}
	std::cerr << "dst: ";
	print(dst);
	std::cerr << std::endl;
	if (!std::equal(src.begin(), src.end(), dst.begin())) {
		std::cerr << "src != dst";
		return false;
	}
	return true;
}

template <class T>
bool packet_pseudorandom_decode_encode()
{
	static_assert(T::size_is_constant);
	std::vector<uint8_t> src, dst;
	src.resize(sizeof(T));
	fill_pseudorandom(src);
	
	packet_message_header_set_requestresponsecode(src.data(), T::RequestResponseCode);
	
	std::cerr << "src: ";
	print(src);
	std::cerr << std::endl;
	
	T packet;
	{
		auto rs = packet_decode(packet, src);
		SPDMCPP_TEST_ASSERT_RS(rs, RetStat::OK);
	}
	{
		auto rs = packet_encode(packet, dst);
		SPDMCPP_TEST_ASSERT_RS(rs, RetStat::OK);
	}
	std::cerr << "dst: ";
	print(dst);
	std::cerr << std::endl;
	if (!std::equal(src.begin(), src.end(), dst.begin())) {
		std::cerr << "src != dst";
		return false;
	}
	
	src.push_back(0xBA);
	{
		auto rs = packet_decode(packet, src);
		SPDMCPP_TEST_ASSERT_RS(rs, RetStat::WARNING_BUFFER_TOO_BIG);
	}
	src.pop_back();
	src.pop_back();
	{
		auto rs = packet_decode(packet, src);
		SPDMCPP_TEST_ASSERT_RS(rs, RetStat::ERROR_BUFFER_TOO_SMALL);
	}
	return true;
}


template <class T>
bool packet_encode_decode(const T& src)
{
	LogClass log(std::cerr);
	log.iprintln("src:");
	src.print_ml(log);
	
	std::vector<uint8_t> buf;
	{
		auto rs = packet_encode(src, buf);
		if (rs != RetStat::OK) {
			std::cerr << "RetStat: " << get_cstr(rs) << std::endl;
			return false;
		}
	}
	print(buf);
	std::cerr << std::endl;
	T dst;
	{
		auto rs = packet_decode(dst, buf);
		if (rs != RetStat::OK) {
			std::cerr << "RetStat: " << get_cstr(rs) << std::endl;
			return false;
		}
	}
	log.iprintln("dst:");
	dst.print_ml(log);
	std::cerr << std::endl;
// 	return src == dst;//TODO ?!
	return true;
}


TEST(packet_pseudorandom_decode_encode, static_size)
{
	EXPECT_TRUE(packet_pseudorandom_decode_encode_basic<packet_message_header>());
// 	EXPECT_TRUE(packet_pseudorandom_decode_encode_basic<packet_error_response_var>());
	EXPECT_TRUE(packet_pseudorandom_decode_encode_basic<packet_version_number>());
	EXPECT_TRUE(packet_pseudorandom_decode_encode_basic<packet_certificate_chain>());
	EXPECT_TRUE(packet_pseudorandom_decode_encode_basic<packet_measurement_block_min>());
	
	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_get_version_response_min>());
// 	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_get_version_response_var>());
	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_get_capabilities_request>());
	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_get_capabilities_response>());
	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_negotiate_algorithms_request_min>());
// 	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_negotiate_algorithms_request_var>());
	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_algorithms_response_min>());
// 	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_algorithms_response_var>());
	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_get_digests_request>());
	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_digests_response_min>());
// 	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_digests_response_var>());
	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_get_certificate_request>());
	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_certificate_response_min>());
// 	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_certificate_response_var>());
	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_challenge_request>());
	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_challenge_auth_response_min>());
// 	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_challenge_auth_response_var>());
	
	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_get_measurements_request_min>());
	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_measurements_response_min>());
	
}
TEST(packet_pseudorandom_decode_encode, variable_size)
{
	//TODO missing some encode/decode functions
	{
		packet_get_version_response_var p;
		fill_pseudorandom_packet(p.Min);
		p.VersionNumberEntries.push_back(return_pseudorandom_type<packet_version_number>());
		p.VersionNumberEntries.push_back(return_pseudorandom_type<packet_version_number>());
// 		EXPECT_TRUE(packet_encode_decode(p));
	}
/*	{
		packet_negotiate_algorithms_request_var var;
		EXPECT_TRUE(packet_encode_decode(var));
	}*/
// 	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_negotiate_algorithms_request_var>());
// 	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_algorithms_response_var>());
// 	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_digests_response_var>());
// 	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_certificate_response_var>());
// 	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_challenge_auth_response_var>());
	
// 	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_get_measurements_request_var>());
// 	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_measurement_block_var>());
// 	EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_measurements_response_var>());
}
