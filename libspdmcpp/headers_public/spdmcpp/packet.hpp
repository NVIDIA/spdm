
#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <limits>

#include <array>
#include <vector>

#include <iostream>

#include <spdmcpp/enum.hpp>
#include <spdmcpp/flag.hpp>
#include <spdmcpp/log.hpp>

namespace spdmcpp
{
	//TODO add packet constructors or some such, for safety of not forgetting to set some parameter?! although it may be a bit annoying to handle layering?
	//TODO move most of the stuff to .cpp files
	//TODO really could use more macros for endian_host_spdm_copy and direct_copy to speed up typing this out and avoid mistakes, assuming there's no pushback against heavy macro usage?
	
	#define SPDMCPP_LOG_expr(log,expr,...) do { (log).print(#expr ": "); (log).print(expr __VA_OPT__(,) __VA_ARGS__); } while(false)
	#define SPDMCPP_LOG_iexprln(log,expr,...) do { (log).iprint(#expr ":\t"); (log).println(expr __VA_OPT__(,) __VA_ARGS__); } while(false)
	#define SPDMCPP_LOG_idataln(log,expr,...) do { (log).iprint(#expr ":\t"); (log).println((expr).data(), (expr.size()) __VA_OPT__(,) __VA_ARGS__); } while(false)
	#define SPDMCPP_LOG_iflagsln(log,flags) do { (log).iprint(#flags ":\t"); (log).println(get_debug_string(flags)); } while(false)
	#define SPDMCPP_LOG_print_ml(log,expr) do { (log).iprintln(#expr ":\t"); (expr).print_ml(log); } while(false)
	
	template <typename T, size_t N>
	constexpr size_t sizeof_array(const T (&array)[N])
	{
		return sizeof(array);
	}
	
	
	struct packet_decode_info
	{
		uint16_t BaseHashSize = 0;
		uint16_t MeasurementHashSize = 0;
		uint16_t SignatureSize = 0;
		uint8_t ChallengeParam2 = 0;
		uint8_t GetMeasurementsParam1 = 0;
		uint8_t GetMeasurementsParam2 = 0;
	};
	
	
	#pragma pack(1)
	
	/// SPDM HEADER structure
	struct packet_message_header
	{
		MessageVersionEnum MessageVersion = MessageVersionEnum::SPDM_1_0;
		RequestResponseEnum RequestResponseCode = RequestResponseEnum::INVALID;
		uint8_t Param1 = 0;
		uint8_t Param2 = 0;
		
		static constexpr bool size_is_constant = true;
		
		packet_message_header() = default;
		packet_message_header(RequestResponseEnum rr) : RequestResponseCode(rr)
		{
		}
		packet_message_header(MessageVersionEnum v, RequestResponseEnum rr) : MessageVersion(v), RequestResponseCode(rr)
		{
		}
		
		void print(LogClass& log) const
		{
			log.print('<');
			SPDMCPP_LOG_expr(log, MessageVersion);			log.print("   ");
			SPDMCPP_LOG_expr(log, RequestResponseCode);		log.print("   ");
			SPDMCPP_LOG_expr(log, Param1);					log.print("   ");
			SPDMCPP_LOG_expr(log, Param2);
			log.print(">");
		}
		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_iexprln(log, MessageVersion);
			SPDMCPP_LOG_iexprln(log, RequestResponseCode);
			SPDMCPP_LOG_iexprln(log, Param1);
			SPDMCPP_LOG_iexprln(log, Param2);
		}
	};
	//TODO there's this magic template library for iterating over members... it'd be really convenient to use it!!!
	
	
	[[nodiscard]] inline MessageVersionEnum packet_message_header_get_version(const uint8_t* buf)
	{
		auto& p = *reinterpret_cast<const packet_message_header*>(buf);
		static_assert(sizeof(p.RequestResponseCode) == 1);
		return p.MessageVersion;
	}
	[[nodiscard]] inline RequestResponseEnum packet_message_header_get_requestresponsecode(const uint8_t* buf)
	{
		auto& p = *reinterpret_cast<const packet_message_header*>(buf);
		static_assert(sizeof(p.RequestResponseCode) == 1);
		return p.RequestResponseCode;
	}
	inline void packet_message_header_set_requestresponsecode(uint8_t* buf, RequestResponseEnum rrcode)
	{
		auto& p = *reinterpret_cast<packet_message_header*>(buf);
		static_assert(sizeof(p.RequestResponseCode) == 1);
		p.RequestResponseCode = rrcode;
	}
/*	inline void endian_swap(packet_message_header& p)//TODO decide, likely not needed?
	{
		endian_swap(p.spdm_version);
		endian_swap(p.RequestResponseCode);
		endian_swap(p.param1);
		endian_swap(p.param2);
	}*/
/*	inline void endian_host_spdm_swap(packet_message_header& p)//TODO decide, likely not needed?
	{
		endian_host_spdm_swap(p.spdm_version);
		endian_host_spdm_swap(p.RequestResponseCode);
		endian_host_spdm_swap(p.param1);
		endian_host_spdm_swap(p.param2);
	}*/
	inline void endian_host_spdm_copy(const packet_message_header& src, packet_message_header& dst)
	{
		endian_host_spdm_copy(src.MessageVersion,			dst.MessageVersion);
		endian_host_spdm_copy(src.RequestResponseCode,	dst.RequestResponseCode);
		endian_host_spdm_copy(src.Param1,					dst.Param1);
		endian_host_spdm_copy(src.Param2,					dst.Param2);
	}
	
	
	//helper for basic types
	template<typename T>
	[[nodiscard]] RetStat packet_decode_basic(T& p, const std::vector<uint8_t>& buf, size_t& start)
	{
		assert(start < buf.size());//TODO need macros for various categories of asserts!!!
		if (start + sizeof(p) > buf.size()) {
			return RetStat::ERROR_BUFFER_TOO_SMALL;
		}
		endian_host_spdm_copy(*reinterpret_cast<const T*>(&buf[start]), p);
		start += sizeof(T);
		return RetStat::OK;
	}
	
	//helper for statically sized structures
	template<typename T>
	[[nodiscard]] RetStat packet_decode_internal(T& p, const std::vector<uint8_t>& buf, size_t& start)
	{
		static_assert(T::size_is_constant);
		assert(start < buf.size());//TODO need macros for various categories of asserts!!!
		if (start + sizeof(p) > buf.size()) {
			return RetStat::ERROR_BUFFER_TOO_SMALL;
		}
		endian_host_spdm_copy(*reinterpret_cast<const T*>(&buf[start]), p);
		start += sizeof(T);
		return RetStat::OK;
	}
	
	template<typename T, typename... Targs>
	[[nodiscard]] RetStat packet_decode(T& p, const std::vector<uint8_t>& buf, size_t& off, Targs... fargs)
	{
		if (off + sizeof(packet_message_header) > buf.size()) {
			return RetStat::ERROR_BUFFER_TOO_SMALL;
		}
		if (packet_message_header_get_requestresponsecode(&buf[off]) != T::RequestResponseCode) {
			return RetStat::ERROR_WRONG_REQUEST_RESPONSE_CODE;
		}
		auto rs = packet_decode_internal(p, buf, off, fargs...);
		if (is_error(rs)) {
			return rs;
		}
		if (off < buf.size()) {
			return RetStat::WARNING_BUFFER_TOO_BIG;
		}
		return rs;
	}
	
	
	template<typename T>
	void packet_encode_basic(const T& p, uint8_t* buf)
	{
		endian_host_spdm_copy(p, *reinterpret_cast<T*>(buf));
	}
	template<typename T>
	void packet_encode_basic(const T& p, std::vector<uint8_t>& buf, size_t& start)
	{
		static_assert(std::is_integral<T>::value || std::is_enum<T>::value);
		if (buf.size() < start + sizeof(p)) {
			buf.resize(start + sizeof(p));
		}
		packet_encode_basic(p, &buf[start]);
		start += sizeof(T);
	}
	template<typename T>
	[[nodiscard]] RetStat packet_encode_internal(const T& p, std::vector<uint8_t>& buf, size_t& start)
	{
		static_assert(T::size_is_constant);
		if (buf.size() < start + sizeof(p)) {
			buf.resize(start + sizeof(p));
		}
		packet_encode_basic(p, &buf[start]);
		start += sizeof(T);
		return RetStat::OK;
	}
	
	template<typename T>
	[[nodiscard]] RetStat packet_encode(const T& p, std::vector<uint8_t>& buf, size_t start = 0)
	{
		auto rs = packet_encode_internal(p, buf, start);
		if (is_error(rs)) {
			return rs;
		}
		if (start + sizeof(p) < buf.size()) {
			return RetStat::WARNING_BUFFER_TOO_BIG;
		}
		return rs;
	}
	
	
	//helpers for simple byte chunks
	[[nodiscard]] inline RetStat packet_decode_basic(uint8_t* dst, size_t size, const std::vector<uint8_t>& buf, size_t& start)
	{
	//	assert(start < buf.size());//TODO need macros for various categories of asserts!!!
		if (start + size > buf.size()) {
			return RetStat::ERROR_BUFFER_TOO_SMALL;
		}
		memcpy(dst, &buf[start], size);
		start += size;
		return RetStat::OK;
	}
	[[nodiscard]] inline RetStat packet_decode_basic(std::vector<uint8_t>& dst, const std::vector<uint8_t>& buf, size_t& start)
	{
		return packet_decode_basic(dst.data(), dst.size(), buf, start);
	}
	template <size_t N>
	[[nodiscard]] RetStat packet_decode_basic(uint8_t (&dst)[N], const std::vector<uint8_t>& buf, size_t& start)
	{
		return packet_decode_basic(dst, N, buf, start);
	}
	
	
	///
	/// SPDM ERROR response
	///
	struct packet_error_response_var
	{
		packet_message_header Header = packet_message_header(RequestResponseCode);
		//TODO handle custom data
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::RESPONSE_ERROR;
		static constexpr bool size_is_constant = false;
		
		void print(LogClass& log) const
		{
			Header.print(log);
			//TODO handle custom data
		}
		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Header);
		}
	};
	
	[[nodiscard]] inline RetStat packet_decode_internal(packet_error_response_var& p, const std::vector<uint8_t>& buf, size_t& off)
	{
		auto rs = packet_decode_internal(p.Header, buf, off);
		//TODO handle custom data
	/*	p.VersionNumberEntries.resize(p.Min.VersionNumberEntryCount);
		for (size_t i = 0; i < p.VersionNumberEntries.size(); ++i) {
			buf = packet_decode_internal(p.VersionNumberEntries[i], buf);
		}*/
		return rs;
	}
	[[nodiscard]] inline RetStat packet_encode_internal(const packet_error_response_var& p, std::vector<uint8_t>& buf, size_t& off)
	{
		//TODO handle custom data
		auto rs = packet_encode_internal(p.Header, buf, off);
		return rs;
	}
	
	///
	/// SPDM VERSION structure
	///
	struct packet_version_number //TODO bitfields are ill-defined endianness-wise iirc!?
	{
		uint16_t Alpha : 4;
		uint16_t UpdateVersionNumber : 4;
		uint16_t MinorVersion : 4;
		uint16_t MajorVersion : 4;
		
		static constexpr bool size_is_constant = true;
		packet_version_number()
		{
			MajorVersion = 0;
			MinorVersion = 0;
			UpdateVersionNumber = 0;
			Alpha = 0;
		}
		MessageVersionEnum getMessageVersion() const
		{
			switch(MajorVersion) {
			case 1:
				switch(MinorVersion) {
					case 0:		return MessageVersionEnum::SPDM_1_0;
					case 1:		return MessageVersionEnum::SPDM_1_1;
				}
			}
			return MessageVersionEnum::UNKNOWN;
		}
		
		void print(LogClass& log) const
		{
			log.print("<");
			SPDMCPP_LOG_expr(log, MajorVersion);			log.print("   ");
			SPDMCPP_LOG_expr(log, MinorVersion);			log.print("   ");
			SPDMCPP_LOG_expr(log, UpdateVersionNumber);		log.print("   ");
			SPDMCPP_LOG_expr(log, Alpha);
			log.print(">");
		}
	};
	
	inline void endian_host_spdm_copy(const packet_version_number& src, packet_version_number& dst)
	{
		dst = src;//TODO surely wrong
	}
	
	///
	/// SPDM CERTIFICATE CHAIN structure
	///
	struct packet_certificate_chain
	{
		uint16_t Length = 0;
		uint16_t Reserved = 0;
		
		static constexpr bool size_is_constant = true;
		
		void print(LogClass& log) const
		{
			log.print("<");
			SPDMCPP_LOG_expr(log, Length);			log.print("   ");
			SPDMCPP_LOG_expr(log, Reserved);		log.print("   ");
			log.print(">");
		}
	};
	
	inline void endian_host_spdm_copy(const packet_certificate_chain& src, packet_certificate_chain& dst)
	{
		endian_host_spdm_copy(src.Length, dst.Length);
		dst.Reserved = src.Reserved;
	}
	
	///
	/// SPDM GET_VERSION request
	///
	struct packet_get_version_request
	{
		packet_message_header Header = packet_message_header(RequestResponseCode);
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::REQUEST_GET_VERSION;
		static constexpr bool size_is_constant = true;
		
		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Header);
		}
	};
	
	inline void endian_host_spdm_copy(const packet_get_version_request& src, packet_get_version_request& dst)
	{
		endian_host_spdm_copy(src.Header, dst.Header);
	}
	
	///
	/// SPDM GET_VERSION response
	///
	struct packet_get_version_response_min
	{
		packet_message_header Header = packet_message_header(RequestResponseCode);
		uint8_t Reserved = 0;
		uint8_t VersionNumberEntryCount = 0;
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::RESPONSE_VERSION;
		static constexpr bool size_is_constant = true;//TODO decide how we need/want to handle such packets
		
		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Header);
			SPDMCPP_LOG_iexprln(log, Reserved);
			SPDMCPP_LOG_iexprln(log, VersionNumberEntryCount);
		}
	};
	
	inline void endian_host_spdm_copy(const packet_get_version_response_min& src, packet_get_version_response_min& dst)
	{
		endian_host_spdm_copy(src.Header,						dst.Header);
		dst.Reserved = src.Reserved;
		endian_host_spdm_copy(src.VersionNumberEntryCount,		dst.VersionNumberEntryCount);
	}
	
	
	struct packet_get_version_response_var
	{
		packet_get_version_response_min Min;
		std::vector<packet_version_number> VersionNumberEntries;
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::RESPONSE_VERSION;
		static constexpr bool size_is_constant = false;//TODO decide how we need/want to handle such packets
		
		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Min);
			
			for (size_t i = 0; i < VersionNumberEntries.size(); ++i) {
				log.iprint("VersionNumberEntries[" + std::to_string(i) + "]: ");//TODO something more optimal
				VersionNumberEntries[i].print(log);
				log.endl();
			}
		}
	};
	
	[[nodiscard]] inline RetStat packet_decode_internal(packet_get_version_response_var& p, const std::vector<uint8_t>& buf, size_t& off)
	{
		auto rs = packet_decode_internal(p.Min, buf, off);
		if (rs != RetStat::OK) {
			return rs;
		}
		p.VersionNumberEntries.resize(p.Min.VersionNumberEntryCount);
		for (size_t i = 0; i < p.VersionNumberEntries.size(); ++i) {
			rs = packet_decode_internal(p.VersionNumberEntries[i], buf, off);
			if (rs != RetStat::OK) {
				return rs;
			}
		}
		return RetStat::OK;
	}
	
	///
	/// SPDM GET_CAPABILITIES request
	///
	struct packet_get_capabilities_request
	{
		packet_message_header Header = packet_message_header(RequestResponseCode);
		uint8_t Reserved0 = 0;
		uint8_t CTExponent = 0;
		uint16_t Reserved1 = 0;
		RequesterCapabilitiesFlags Flags = RequesterCapabilitiesFlags::NIL;
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::REQUEST_GET_CAPABILITIES;
		static constexpr bool size_is_constant = true;
		
		packet_get_capabilities_request() = default;
		packet_get_capabilities_request(uint8_t ct_exponent, RequesterCapabilitiesFlags flags) : CTExponent(ct_exponent), Flags(flags)
		{
		}
		
		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Header);
			SPDMCPP_LOG_iexprln(log, Reserved0);
			SPDMCPP_LOG_iexprln(log, CTExponent);
			SPDMCPP_LOG_iexprln(log, Reserved1);
			SPDMCPP_LOG_iflagsln(log, Flags);
		}
	};
	
	inline void endian_host_spdm_copy(const packet_get_capabilities_request& src, packet_get_capabilities_request& dst)
	{
		endian_host_spdm_copy(src.Header,		dst.Header);
		dst.Reserved0 = src.Reserved0;
		endian_host_spdm_copy(src.CTExponent,	dst.CTExponent);
		dst.Reserved1 = src.Reserved1;
		endian_host_spdm_copy(src.Flags,		dst.Flags);
	}
	
	
	///
	/// SPDM GET_CAPABILITIES response
	///
	struct packet_get_capabilities_response
	{
		packet_message_header Header = packet_message_header(RequestResponseCode);
		uint8_t Reserved0 = 0;
		uint8_t CTExponent = 0;
		uint16_t Reserved1 = 0;
		ResponderCapabilitiesFlags Flags = ResponderCapabilitiesFlags::NIL;
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::RESPONSE_CAPABILITIES;
		static constexpr bool size_is_constant = true;
		
		packet_get_capabilities_response() = default;
		packet_get_capabilities_response(uint8_t ct_exponent, ResponderCapabilitiesFlags flags) : CTExponent(ct_exponent), Flags(flags)
		{
		}
		
		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Header);
			SPDMCPP_LOG_iexprln(log, Reserved0);
			SPDMCPP_LOG_iexprln(log, CTExponent);
			SPDMCPP_LOG_iexprln(log, Reserved1);
			SPDMCPP_LOG_iflagsln(log, Flags);
		}
	};
	
	inline void endian_host_spdm_copy(const packet_get_capabilities_response& src, packet_get_capabilities_response& dst)
	{
		endian_host_spdm_copy(src.Header,		dst.Header);
		endian_host_spdm_copy(src.Reserved0,	dst.Reserved0);
		endian_host_spdm_copy(src.CTExponent,	dst.CTExponent);
		endian_host_spdm_copy(src.Reserved1,	dst.Reserved1);
		endian_host_spdm_copy(src.Flags,		dst.Flags);
	}
	
	
	
	///
	/// SPDM NEGOTIATE_ALGORITHMS request
	///
	struct PacketReqAlgStruct
	{
		AlgTypeEnum AlgType = AlgTypeEnum::UNKNOWN;
		uint8_t AlgCount = 0;
		uint8_t AlgSupported[14] = { 0 };//TODO is this really the limit?
		uint32_t AlgExternal[15] = { 0 };//TODO is this really is the limit?
		
// 		static constexpr bool size_is_constant = false;
		static PacketReqAlgStruct buildSupported2(AlgTypeEnum type, uint8_t algsup0, uint8_t algsup1)
		{
			PacketReqAlgStruct ret;
			ret.AlgType = type;
			ret.setFixedAlgCount(2);
			ret.AlgSupported[0] = algsup0;
			ret.AlgSupported[1] = algsup1;
			return ret;
		}
		
		void setFixedAlgCount(uint8_t count)
		{
			AlgCount &= 0xF0;
			AlgCount |= count << 4;
		}
		void setExtAlgCount(uint8_t count)
		{
			AlgCount &= 0xF;
			AlgCount |= count & 0xF;
		}
		uint8_t getFixedAlgCount() const
		{
			return AlgCount >> 4;
		}
		uint8_t getExtAlgCount() const
		{
			return AlgCount & 0xF;
		}
		//TODO need many more helpers?!
		
		uint16_t get_size() const
		{
			size_t size = 0;
			size += sizeof(AlgType);
			size += sizeof(AlgCount);
			size += getFixedAlgCount() * sizeof(AlgSupported[0]);
			size += getExtAlgCount() * sizeof(AlgExternal[0]);
			assert(size <= std::numeric_limits<uint16_t>::max());
			return static_cast<uint16_t>(size);
		}
		
		void print(LogClass& log) const
		{
			log.print("<");
			SPDMCPP_LOG_expr(log, AlgType);			log.print("   ");
			SPDMCPP_LOG_expr(log, AlgCount);		log.print("   ");
		//	SPDMCPP_LOG_expr(log, AlgSupported);
			//TODO support printing
			log.print(">");
		}
	};
	
	[[nodiscard]] inline RetStat packet_encode_internal(const PacketReqAlgStruct& p, std::vector<uint8_t>& buf, size_t& start)
	{
		size_t off = start;
		buf.resize(start + p.get_size());
		packet_encode_basic(p.AlgType, buf, off);
		packet_encode_basic(p.AlgCount, buf, off);
		for (uint8_t i = 0; i < p.getFixedAlgCount(); ++i) {
			packet_encode_basic(p.AlgSupported[i], buf, off);
		}
		for (uint8_t i = 0; i < p.getExtAlgCount(); ++i) {
			packet_encode_basic(p.AlgExternal[i], buf, off);
		}
		start = off;
		return RetStat::OK;
	}
	[[nodiscard]] inline RetStat packet_decode_internal(PacketReqAlgStruct& p, const std::vector<uint8_t>& buf, size_t& off)
	{
		auto rs = packet_decode_basic(p.AlgType, buf, off);
		if (is_error(rs))
			return rs;
		rs = packet_decode_basic(p.AlgCount, buf, off);
		if (is_error(rs))
			return rs;
		//TODO validate p.AlgType & Count?
		for (uint8_t i = 0; i < p.getFixedAlgCount(); ++i) {
			rs = packet_decode_basic(p.AlgSupported[i], buf, off);
			if (is_error(rs))
				return rs;
		}
		for (uint8_t i = 0; i < p.getExtAlgCount(); ++i) {
			rs = packet_decode_basic(p.AlgExternal[i], buf, off);
			if (is_error(rs))
				return rs;
		}
		return RetStat::OK;
	}
	
	
	
	struct packet_negotiate_algorithms_request_min
	{
		packet_message_header Header = packet_message_header(RequestResponseCode);
		uint16_t Length = 0;
		uint8_t MeasurementSpecification = 0;
		uint8_t Reserved0 = 0;
		BaseAsymAlgoFlags BaseAsymAlgo = BaseAsymAlgoFlags::NIL;
		BaseHashAlgoFlags BaseHashAlgo = BaseHashAlgoFlags::NIL;
		uint32_t Reserved1 = 0;
		uint32_t Reserved2 = 0;
		uint32_t Reserved3 = 0;
		uint8_t ExtAsymCount = 0;
		uint8_t ExtHashCount = 0;
		uint16_t Reserved4 = 0;
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::REQUEST_NEGOTIATE_ALGORITHMS;
		static constexpr bool size_is_constant = true;
		
		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Header);
			SPDMCPP_LOG_iexprln(log, Length);
			SPDMCPP_LOG_iexprln(log, MeasurementSpecification);
			SPDMCPP_LOG_iexprln(log, Reserved0);
			SPDMCPP_LOG_iflagsln(log, BaseAsymAlgo);
			SPDMCPP_LOG_iflagsln(log, BaseHashAlgo);
			SPDMCPP_LOG_iexprln(log, Reserved1);
			SPDMCPP_LOG_iexprln(log, Reserved2);
			SPDMCPP_LOG_iexprln(log, Reserved3);
			SPDMCPP_LOG_iexprln(log, ExtAsymCount);
			SPDMCPP_LOG_iexprln(log, ExtHashCount);
			SPDMCPP_LOG_iexprln(log, Reserved4);
		}
	};
	
	inline void endian_host_spdm_copy(const packet_negotiate_algorithms_request_min& src, packet_negotiate_algorithms_request_min& dst)
	{
		endian_host_spdm_copy(src.Header,						dst.Header);
		endian_host_spdm_copy(src.Length,						dst.Length);
		endian_host_spdm_copy(src.MeasurementSpecification,		dst.MeasurementSpecification);
		dst.Reserved0 = src.Reserved0;
		endian_host_spdm_copy(src.BaseAsymAlgo,					dst.BaseAsymAlgo);
		endian_host_spdm_copy(src.BaseHashAlgo,					dst.BaseHashAlgo);
		dst.Reserved1 = src.Reserved1;
		dst.Reserved2 = src.Reserved2;
		dst.Reserved3 = src.Reserved3;
		endian_host_spdm_copy(src.ExtAsymCount,					dst.ExtAsymCount);
		endian_host_spdm_copy(src.ExtHashCount,					dst.ExtHashCount);
		dst.Reserved4 = src.Reserved4;
	}
	
	
	struct packet_negotiate_algorithms_request_var
	{
		typedef packet_negotiate_algorithms_request_min MinType;
		MinType Min;
		
		std::vector<PacketReqAlgStruct> PacketReqAlgVector;
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::REQUEST_NEGOTIATE_ALGORITHMS;
		static constexpr bool size_is_constant = false;
		
		uint16_t get_size() const
		{
			size_t size = 0;
			size += sizeof(Min);
			for (const auto& iter : PacketReqAlgVector) {
				size += iter.get_size();
			}
			assert(size <= std::numeric_limits<uint16_t>::max());
			return static_cast<uint16_t>(size);
		}
		RetStat finalize()
		{
			if (PacketReqAlgVector.size() >= 256) {
				return RetStat::ERROR_UNKNOWN;
			}
			Min.Header.Param1 = static_cast<uint8_t>(PacketReqAlgVector.size());
			Min.Length = get_size();
			return RetStat::OK;
		}
		
		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Min);
			
			SPDMCPP_LOG_iexprln(log, PacketReqAlgVector.size());//TODO template for vector?!
			for (size_t i = 0; i < PacketReqAlgVector.size(); ++i) {
				log.iprint("PacketReqAlgVector[" + std::to_string(i) + "]: ");//TODO something more optimal
				PacketReqAlgVector[i].print(log);
				log.endl();
			}
		}
	};
	
	[[nodiscard]] inline RetStat packet_encode_internal(const packet_negotiate_algorithms_request_var& p, std::vector<uint8_t>& buf, size_t& off)
	{
		buf.resize(off + p.Min.Length);
		auto rs = packet_encode_internal(p.Min, buf, off);
		
		for (const auto& iter : p.PacketReqAlgVector) {
			rs = packet_encode_internal(iter, buf, off);
			if (is_error(rs))
				return rs;
		}
		return rs;
	}
#if 0
	[[nodiscard]] inline RetStat packet_decode_internal(packet_negotiate_algorithms_request_var& p, const std::vector<uint8_t>& buf, size_t& start)
	{
		auto rs = packet_decode_internal(p.Min, buf, start);
	/*	p.VersionNumberEntries.resize(p.Min.VersionNumberEntryCount);
		for (size_t i = 0; i < p.VersionNumberEntries.size(); ++i) {
			buf = packet_decode_internal(p.VersionNumberEntries[i], buf);
		}*/
		return rs;
	}
#endif
	
	///
	/// SPDM NEGOTIATE_ALGORITHMS response
	///
	struct packet_algorithms_response_min
	{
		packet_message_header Header = packet_message_header(RequestResponseCode);
		uint16_t Length = 0;
		uint8_t MeasurementSpecification = 0;
		uint8_t Reserved0 = 0;
		MeasurementHashAlgoFlags MeasurementHashAlgo = MeasurementHashAlgoFlags::NIL;
		BaseAsymAlgoFlags BaseAsymAlgo = BaseAsymAlgoFlags::NIL;
		BaseHashAlgoFlags BaseHashAlgo = BaseHashAlgoFlags::NIL;
		uint32_t Reserved1 = 0;
		uint32_t Reserved2 = 0;
		uint32_t Reserved3 = 0;
		uint8_t ExtAsymCount = 0;
		uint8_t ExtHashCount = 0;
		uint16_t Reserved4 = 0;
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::RESPONSE_ALGORITHMS;
		static constexpr bool size_is_constant = true;//TODO decide how we need/want to handle such packets
		
		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Header);
			SPDMCPP_LOG_iexprln(log, Length);
			SPDMCPP_LOG_iexprln(log, MeasurementSpecification);
			SPDMCPP_LOG_iexprln(log, Reserved0);
			SPDMCPP_LOG_iflagsln(log, MeasurementHashAlgo);
			SPDMCPP_LOG_iflagsln(log, BaseAsymAlgo);
			SPDMCPP_LOG_iflagsln(log, BaseHashAlgo);
			SPDMCPP_LOG_iexprln(log, Reserved1);
			SPDMCPP_LOG_iexprln(log, Reserved2);
			SPDMCPP_LOG_iexprln(log, Reserved3);
			SPDMCPP_LOG_iexprln(log, ExtAsymCount);
			SPDMCPP_LOG_iexprln(log, ExtHashCount);
			SPDMCPP_LOG_iexprln(log, Reserved4);
		}
	};
	
	inline void endian_host_spdm_copy(const packet_algorithms_response_min& src, packet_algorithms_response_min& dst)
	{
		endian_host_spdm_copy(src.Header,						dst.Header);
		endian_host_spdm_copy(src.Length,						dst.Length);
		endian_host_spdm_copy(src.MeasurementSpecification,		dst.MeasurementSpecification);
		dst.Reserved0 = src.Reserved0;
		endian_host_spdm_copy(src.MeasurementHashAlgo,			dst.MeasurementHashAlgo);
		endian_host_spdm_copy(src.BaseAsymAlgo,					dst.BaseAsymAlgo);
		endian_host_spdm_copy(src.BaseHashAlgo,					dst.BaseHashAlgo);
		dst.Reserved1 = src.Reserved1;
		dst.Reserved2 = src.Reserved2;
		dst.Reserved3 = src.Reserved3;
		endian_host_spdm_copy(src.ExtAsymCount,					dst.ExtAsymCount);
		endian_host_spdm_copy(src.ExtHashCount,					dst.ExtHashCount);
		dst.Reserved4 = src.Reserved4;
	}


	struct packet_algorithms_response_var
	{
		packet_algorithms_response_min Min;
		std::vector<PacketReqAlgStruct> PacketReqAlgVector;
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::RESPONSE_ALGORITHMS;
		static constexpr bool size_is_constant = false;//TODO decide how we need/want to handle such packets
		
		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Min);
			SPDMCPP_LOG_iexprln(log, PacketReqAlgVector.size());
			for (size_t i = 0; i < PacketReqAlgVector.size(); ++i) {
				log.iprint("PacketReqAlgVector[" + std::to_string(i) + "]: ");//TODO something more optimal
				PacketReqAlgVector[i].print(log);
				log.endl();
			}
		}
	};
	
	[[nodiscard]] inline RetStat packet_encode_internal(const packet_algorithms_response_var& p, std::vector<uint8_t>& buf, size_t& off)
	{
		auto rs = packet_encode_internal(p.Min, buf, off);
		
	/*	p.VersionNumberEntries.resize(p.Min.VersionNumberEntryCount);
		for (size_t i = 0; i < p.VersionNumberEntries.size(); ++i) {
			buf = packet_decode_internal(p.VersionNumberEntries[i], buf);
		}*/
		return rs;
	}
	[[nodiscard]] inline RetStat packet_decode_internal(packet_algorithms_response_var& p, const std::vector<uint8_t>& buf, size_t& off)
	{
		auto rs = packet_decode_internal(p.Min, buf, off);
		if (is_error(rs))
			return rs;
		
		p.PacketReqAlgVector.resize(p.Min.Header.Param1);//TODO check size for reasonable limit!!
		for (size_t i = 0; i < p.PacketReqAlgVector.size(); ++i) {
			rs = packet_decode_internal(p.PacketReqAlgVector[i], buf, off);
			if (is_error(rs))
				return rs;
		}
	/*	for (const auto& iter : p.PacketReqAlgVector) {
			auto rs = packet_encode_internal(iter, buf, off);
			if (is_error(rs)) {
				return rs;
			}
		}*/
		return rs;
	}
	

	///
	/// SPDM GET_DIGESTS request
	///
	struct packet_get_digests_request
	{
		packet_message_header Header = packet_message_header(RequestResponseCode);
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::REQUEST_GET_DIGESTS;
		static constexpr bool size_is_constant = true;

		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Header);
		}
	};

	inline void endian_host_spdm_copy(const packet_get_digests_request& src, packet_get_digests_request& dst)
	{
		endian_host_spdm_copy(src.Header, dst.Header);
	}


	///
	/// SPDM DIGESTS response
	///
	struct packet_digests_response_min
	{
		packet_message_header Header = packet_message_header(RequestResponseCode);
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::RESPONSE_DIGESTS;
		static constexpr bool size_is_constant = true;

		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Header);
		}
	};
	inline void endian_host_spdm_copy(const packet_digests_response_min& src, packet_digests_response_min& dst)
	{
		endian_host_spdm_copy(src.Header, dst.Header);
	}


	struct packet_hash_sha_386//TODO the hash size is not fixed!!!
	{
		uint8_t Value[48];
		static constexpr bool size_is_constant = true;

		void print(LogClass& log) const
		{
			log.print(Value, sizeof_array(Value));
		}
	};

	struct packet_digests_response_var
	{
		packet_digests_response_min Min;
		std::vector<std::vector<uint8_t>> DigestVector;//TODO the hash size is not fixed!!!

		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::RESPONSE_DIGESTS;
		static constexpr bool size_is_constant = false;

		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Min);
			SPDMCPP_LOG_iexprln(log, DigestVector.size());
			for (size_t i = 0; i < DigestVector.size(); ++i) {
				log.iprint("DigestVector[" + std::to_string(i) + "]: ");//TODO something more optimal
				log.print(DigestVector[i].data(), DigestVector[i].size());
				log.endl();
			}
		}
	};

	[[nodiscard]] inline RetStat packet_decode_internal(packet_digests_response_var& p, const std::vector<uint8_t>& buf, size_t& off, const packet_decode_info& info)
	{
		auto rs = packet_decode_internal(p.Min, buf, off);
		if (is_error(rs))
			return rs;

		p.DigestVector.resize(count_bits(p.Min.Header.Param2));//TODO check size for reasonable limit!!
		for (size_t i = 0; i < p.DigestVector.size(); ++i) {
			p.DigestVector[i].resize(info.BaseHashSize);
			rs = packet_decode_basic(p.DigestVector[i], buf, off);
			if (is_error(rs))
				return rs;
		}
		return RetStat::OK;
	}


	///
	/// SPDM GET_CERTIFICATE request
	///
	struct packet_get_certificate_request
	{
		packet_message_header Header = packet_message_header(RequestResponseCode);
		uint16_t Offset = 0;
		uint16_t Length = 0;
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::REQUEST_GET_CERTIFICATE;
		static constexpr bool size_is_constant = true;

		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Header);
			SPDMCPP_LOG_iexprln(log, Offset);
			SPDMCPP_LOG_iexprln(log, Length);
		}
	};

	inline void endian_host_spdm_copy(const packet_get_certificate_request& src, packet_get_certificate_request& dst)
	{
		endian_host_spdm_copy(src.Header, dst.Header);
		endian_host_spdm_copy(src.Offset, dst.Offset);
		endian_host_spdm_copy(src.Length, dst.Length);
	}


	///
	/// SPDM CERTIFICATE response
	///
	struct packet_certificate_response_min
	{
		packet_message_header Header = packet_message_header(RequestResponseCode);
		uint16_t PortionLength = 0;
		uint16_t RemainderLength = 0;
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::RESPONSE_CERTIFICATE;
		static constexpr bool size_is_constant = true;

		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Header);
			SPDMCPP_LOG_iexprln(log, PortionLength);
			SPDMCPP_LOG_iexprln(log, RemainderLength);
		}
	};

	inline void endian_host_spdm_copy(const packet_certificate_response_min& src, packet_certificate_response_min& dst)
	{
		endian_host_spdm_copy(src.Header, dst.Header);
		endian_host_spdm_copy(src.PortionLength, dst.PortionLength);
		endian_host_spdm_copy(src.RemainderLength, dst.RemainderLength);
	}


	struct packet_certificate_response_var
	{
		packet_certificate_response_min Min;
		std::vector<uint8_t> CertificateVector;

		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::RESPONSE_CERTIFICATE;
		static constexpr bool size_is_constant = false;

		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Min);
			SPDMCPP_LOG_iexprln(log, CertificateVector.size());
			if (!CertificateVector.empty())
				SPDMCPP_LOG_idataln(log, CertificateVector);
		}
	};

	[[nodiscard]] inline RetStat packet_decode_internal(packet_certificate_response_var& p, const std::vector<uint8_t>& buf, size_t& off)
	{
		auto rs = packet_decode_internal(p.Min, buf, off);
		if (is_error(rs))
			return rs;

		p.CertificateVector.resize(p.Min.PortionLength);
		memcpy(p.CertificateVector.data(), &buf[off], p.CertificateVector.size());
		off += p.CertificateVector.size();

		return RetStat::OK;
	}



	///
	/// SPDM CHALLENGE request
	///
	struct packet_challenge_request
	{
		packet_message_header Header = packet_message_header(RequestResponseCode);
		uint8_t Nonce[32] = { 0 };
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::REQUEST_CHALLENGE;
		static constexpr bool size_is_constant = true;

		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Header);
			log.iprint("Nonce[32]: ");
			log.println(Nonce, sizeof_array(Nonce));
		}
	};

	inline void endian_host_spdm_copy(const packet_challenge_request& src, packet_challenge_request& dst)
	{
		endian_host_spdm_copy(src.Header, dst.Header);
		memcpy(dst.Nonce, src.Nonce, sizeof(dst.Nonce));
	}


	///
	/// SPDM CERTIFICATE response
	///
	struct packet_challenge_auth_response_min
	{
		packet_message_header Header = packet_message_header(RequestResponseCode);
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::RESPONSE_CHALLENGE_AUTH;
		static constexpr bool size_is_constant = true;

		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Header);
		}
	};

	inline void endian_host_spdm_copy(const packet_challenge_auth_response_min& src, packet_challenge_auth_response_min& dst)
	{
		endian_host_spdm_copy(src.Header, dst.Header);
	}


	struct packet_challenge_auth_response_var
	{
		packet_challenge_auth_response_min Min;
		uint8_t Nonce[32] = { 0 };
		std::vector<uint8_t> CertChainHashVector;
		std::vector<uint8_t> MeasurementSummaryHashVector;
		std::vector<uint8_t> OpaqueDataVector;
		std::vector<uint8_t> SignatureVector;
		uint16_t OpaqueLength = 0;

		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::RESPONSE_CHALLENGE_AUTH;
		static constexpr bool size_is_constant = false;

		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Min);
			log.iprint("Nonce[32]: ");
			log.println(Nonce, sizeof_array(Nonce));
			SPDMCPP_LOG_idataln(log, CertChainHashVector);
			SPDMCPP_LOG_idataln(log, MeasurementSummaryHashVector);
			SPDMCPP_LOG_iexprln(log, OpaqueLength);
			SPDMCPP_LOG_idataln(log, OpaqueDataVector);
			SPDMCPP_LOG_idataln(log, SignatureVector);
		}
	};

	[[nodiscard]] inline RetStat packet_decode_internal(packet_challenge_auth_response_var& p, const std::vector<uint8_t>& buf, size_t& off, const packet_decode_info& info)
	{
		auto rs = packet_decode_internal(p.Min, buf, off);
		if (is_error(rs))
			return rs;

		p.CertChainHashVector.resize(info.BaseHashSize);
		rs = packet_decode_basic(p.CertChainHashVector, buf, off);
		if (is_error(rs))
			return rs;
		
		rs = packet_decode_basic(p.Nonce, buf, off);
		if (is_error(rs))
			return rs;
		
		if (info.ChallengeParam2) {
			p.MeasurementSummaryHashVector.resize(info.BaseHashSize);
			rs = packet_decode_basic(p.MeasurementSummaryHashVector, buf, off);
			if (is_error(rs))
				return rs;
		}
		rs = packet_decode_basic(p.OpaqueLength, buf, off);//TODO verify no greater than 1024
		if (is_error(rs))
			return rs;
		p.OpaqueDataVector.resize(p.OpaqueLength);
		rs = packet_decode_basic(p.OpaqueDataVector, buf, off);
		if (is_error(rs))
			return rs;
		
		p.SignatureVector.resize(info.SignatureSize);
		rs = packet_decode_basic(p.SignatureVector, buf, off);
		return RetStat::OK;
	}




	///
	/// SPDM GET_MEASUREMENTS request
	///
	struct packet_get_measurements_request_min
	{
		packet_message_header Header = packet_message_header(RequestResponseCode);
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::REQUEST_GET_MEASUREMENTS;
		static constexpr bool size_is_constant = true;
		
		bool has_nonce() const { return Header.Param1 & 0x01; }
		void set_nonce() { Header.Param1 |= 0x01; }
		
		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Header);
		}
	};

	inline void endian_host_spdm_copy(const packet_get_measurements_request_min& src, packet_get_measurements_request_min& dst)
	{
		endian_host_spdm_copy(src.Header, dst.Header);
	}


	struct packet_get_measurements_request_var
	{
		packet_get_measurements_request_min Min;
		uint8_t Nonce[32] = { 0 };
		uint8_t SlotIDParam = 0;
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::REQUEST_GET_MEASUREMENTS;
		static constexpr bool size_is_constant = false;
		
		bool has_nonce() const { return Min.has_nonce(); }
		void set_nonce() { Min.set_nonce(); }
		
		uint16_t get_size() const
		{
			size_t size = 0;
			size += sizeof(Min);
			if (Min.has_nonce()) {
				size += sizeof(Nonce);
				size += sizeof(SlotIDParam);
			}
			assert(size <= std::numeric_limits<uint16_t>::max());
			return static_cast<uint16_t>(size);
		}
		
		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Min);
			log.iprint("Nonce[32]: ");
			log.println(Nonce, sizeof_array(Nonce));
			SPDMCPP_LOG_iexprln(log, SlotIDParam);
		}
	};


	[[nodiscard]] inline RetStat packet_encode_internal(const packet_get_measurements_request_var& p, std::vector<uint8_t>& buf, size_t& off)
	{
		size_t size = p.get_size();
		buf.resize(off + size);
		
		auto rs = packet_encode_internal(p.Min, buf, off);
		if (is_error(rs))
			return rs;
		
		if (p.has_nonce()) {
		//	packet_encode_basic(p.Nonce, buf, off);
			memcpy(&buf[off], p.Nonce, sizeof(p.Nonce));
			off += sizeof(p.Nonce);
			
			packet_encode_basic(p.SlotIDParam, buf, off);
		}
		return rs;
	}
	
	///
	/// SPDM MEASUREMENT BLOCK structure
	///
	struct packet_measurement_block_min
	{
		uint8_t Index = 0;
		uint8_t MeasurementSpecification = 0;
		uint16_t MeasurementSize = 0;
		
		static constexpr bool size_is_constant = true;
		
		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_iexprln(log, Index);						log.print("   ");
			SPDMCPP_LOG_iexprln(log, MeasurementSpecification);		log.print("   ");
			SPDMCPP_LOG_iexprln(log, MeasurementSize);				log.print("   ");
		}
	};
	
	inline void endian_host_spdm_copy(const packet_measurement_block_min& src, packet_measurement_block_min& dst)
	{
		endian_host_spdm_copy(src.Index, dst.Index);
		endian_host_spdm_copy(src.MeasurementSpecification, dst.MeasurementSpecification);
		endian_host_spdm_copy(src.MeasurementSize, dst.MeasurementSize);
	}
	
	struct packet_measurement_block_var
	{
		packet_measurement_block_min Min;
		std::vector<uint8_t> MeasurementVector;

		static constexpr bool size_is_constant = false;

		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Min);
			SPDMCPP_LOG_idataln(log, MeasurementVector);
		}
	};

	[[nodiscard]] inline RetStat packet_decode_internal(packet_measurement_block_var& p, const std::vector<uint8_t>& buf, size_t& off)
	{
		auto rs = packet_decode_basic(p.Min, buf, off);
		if (is_error(rs))
			return rs;

		p.MeasurementVector.resize(p.Min.MeasurementSize);
		rs = packet_decode_basic(p.MeasurementVector, buf, off);
		return rs;
	}

	///
	/// SPDM MEASUREMENTS response
	///
	struct packet_measurements_response_min
	{
		packet_message_header Header = packet_message_header(RequestResponseCode);
		uint8_t NumberOfBlocks = 0;
		uint8_t MeasurementRecordLength[3] = { 0, 0, 0 };//wtf dmtf...
		
		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::RESPONSE_MEASUREMENTS;
		static constexpr bool size_is_constant = true;
		
		uint32_t get_measurement_record_length() const { return MeasurementRecordLength[0] | MeasurementRecordLength[1] << 8 | MeasurementRecordLength[2] << 16; }
		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Header);
			SPDMCPP_LOG_iexprln(log, NumberOfBlocks);
			log.iprint("MeasurementRecordLength[3]: ");
			log.println(MeasurementRecordLength, sizeof_array(MeasurementRecordLength));
		}
	};

	inline void endian_host_spdm_copy(const packet_measurements_response_min& src, packet_measurements_response_min& dst)
	{
		endian_host_spdm_copy(src.Header, dst.Header);
		endian_host_spdm_copy(src.NumberOfBlocks, dst.NumberOfBlocks);
	#if SPDMCPP_ENDIAN_SWAP
		dst.MeasurementRecordLength[0] = src.MeasurementRecordLength[2];
		dst.MeasurementRecordLength[1] = src.MeasurementRecordLength[1];
		dst.MeasurementRecordLength[2] = src.MeasurementRecordLength[0];
	#else
		dst.MeasurementRecordLength[0] = src.MeasurementRecordLength[0];
		dst.MeasurementRecordLength[1] = src.MeasurementRecordLength[1];
		dst.MeasurementRecordLength[2] = src.MeasurementRecordLength[2];
	#endif
	}


	struct packet_measurements_response_var	//TODO all variable packets don't need to be packed
	{
		packet_measurements_response_min Min;
		uint8_t Nonce[32] = { 0 };
		std::vector<packet_measurement_block_var> MeasurementBlockVector;
		std::vector<uint8_t> OpaqueDataVector;
		std::vector<uint8_t> SignatureVector;
		uint16_t OpaqueLength = 0;

		static constexpr RequestResponseEnum RequestResponseCode = RequestResponseEnum::RESPONSE_MEASUREMENTS;
		static constexpr bool size_is_constant = false;

		void print_ml(LogClass& log) const
		{
			SPDMCPP_LOG_INDENT(log);
			SPDMCPP_LOG_print_ml(log, Min);
			log.iprint("Nonce[32]: ");
			log.println(Nonce, sizeof_array(Nonce));
			
			SPDMCPP_LOG_iexprln(log, MeasurementBlockVector.size());
			for (size_t i = 0; i < MeasurementBlockVector.size(); ++i) {
				log.iprintln("MeasurementBlockVector[" + std::to_string(i) + "]:");//TODO something more optimal
				MeasurementBlockVector[i].print_ml(log);
			}
			
			SPDMCPP_LOG_iexprln(log, OpaqueLength);
			SPDMCPP_LOG_idataln(log, OpaqueDataVector);
			SPDMCPP_LOG_idataln(log, SignatureVector);
		}
	};

	[[nodiscard]] inline RetStat packet_decode_internal(packet_measurements_response_var& p, const std::vector<uint8_t>& buf, size_t& off, const packet_decode_info& info)
	{
		auto rs = packet_decode_internal(p.Min, buf, off);
		if (is_error(rs))
			return rs;
		
		{
			size_t end = off + p.Min.get_measurement_record_length();
			while (off < end) {
				p.MeasurementBlockVector.resize(p.MeasurementBlockVector.size() + 1);
				rs = packet_decode_internal(p.MeasurementBlockVector.back(), buf, off);
				if (is_error(rs))
					return rs;
			}
			if (off != end) {
				assert(false);	//TODO remove
				return RetStat::ERROR_UNKNOWN;
			}
		}
		rs = packet_decode_basic(p.Nonce, buf, off);
		if (is_error(rs))
			return rs;
		
		rs = packet_decode_basic(p.OpaqueLength, buf, off);//TODO verify no greater than 1024
		if (is_error(rs))
			return rs;
		
		p.OpaqueDataVector.resize(p.OpaqueLength);
		rs = packet_decode_basic(p.OpaqueDataVector, buf, off);
		if (is_error(rs))
			return rs;
		
		if (info.GetMeasurementsParam1 & 0x01) {
			p.SignatureVector.resize(info.SignatureSize);
			rs = packet_decode_basic(p.SignatureVector, buf, off);
		}
		
		return rs;
	}

	
	#pragma pack()
	
	#undef SPDMCPP_LOG_expr
	#undef SPDMCPP_LOG_iexprln
	#undef SPDMCPP_LOG_iflagsln
	#undef SPDMCPP_LOG_print_ml
}
