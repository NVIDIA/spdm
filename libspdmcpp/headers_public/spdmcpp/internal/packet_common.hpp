
#pragma once

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
    {}
    packet_message_header(MessageVersionEnum v, RequestResponseEnum rr) :
        MessageVersion(v), RequestResponseCode(rr)
    {}

    void print(LogClass& log) const
    {
        log.print('<');
        SPDMCPP_LOG_expr(log, MessageVersion);
        log.print("   ");
        SPDMCPP_LOG_expr(log, RequestResponseCode);
        log.print("   ");
        SPDMCPP_LOG_expr(log, Param1);
        log.print("   ");
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

// TODO there's this magic template library for iterating over members... it'd
// be really convenient to use it!!!

[[nodiscard]] inline MessageVersionEnum
    packet_message_header_get_version(const uint8_t* buf)
{
    auto& p = *reinterpret_cast<const packet_message_header*>(buf);
    static_assert(sizeof(p.RequestResponseCode) == 1);
    return p.MessageVersion;
}
[[nodiscard]] inline RequestResponseEnum
    packet_message_header_get_requestresponsecode(const uint8_t* buf)
{
    auto& p = *reinterpret_cast<const packet_message_header*>(buf);
    static_assert(sizeof(p.RequestResponseCode) == 1);
    return p.RequestResponseCode;
}
inline void
    packet_message_header_set_requestresponsecode(uint8_t* buf,
                                                  RequestResponseEnum rrcode)
{
    auto& p = *reinterpret_cast<packet_message_header*>(buf);
    static_assert(sizeof(p.RequestResponseCode) == 1);
    p.RequestResponseCode = rrcode;
}
/*	inline void endian_swap(packet_message_header& p)//TODO decide, likely not
   needed?
    {
        endian_swap(p.spdm_version);
        endian_swap(p.RequestResponseCode);
        endian_swap(p.param1);
        endian_swap(p.param2);
    }*/
/*	inline void endian_host_spdm_swap(packet_message_header& p)//TODO decide,
   likely not needed?
    {
        endian_host_spdm_swap(p.spdm_version);
        endian_host_spdm_swap(p.RequestResponseCode);
        endian_host_spdm_swap(p.param1);
        endian_host_spdm_swap(p.param2);
    }*/
inline void endian_host_spdm_copy(const packet_message_header& src,
                                  packet_message_header& dst)
{
    endian_host_spdm_copy(src.MessageVersion, dst.MessageVersion);
    endian_host_spdm_copy(src.RequestResponseCode, dst.RequestResponseCode);
    endian_host_spdm_copy(src.Param1, dst.Param1);
    endian_host_spdm_copy(src.Param2, dst.Param2);
}

// helper for basic types
template <typename T>
[[nodiscard]] RetStat packet_decode_basic(T& p, const std::vector<uint8_t>& buf,
                                          size_t& start)
{
    assert(start <
           buf.size()); // TODO need macros for various categories of asserts!!!
    if (start + sizeof(p) > buf.size())
    {
        return RetStat::ERROR_BUFFER_TOO_SMALL;
    }
    endian_host_spdm_copy(*reinterpret_cast<const T*>(&buf[start]), p);
    start += sizeof(T);
    return RetStat::OK;
}

// helper for statically sized structures
template <typename T>
[[nodiscard]] RetStat
    packet_decode_internal(T& p, const std::vector<uint8_t>& buf, size_t& start)
{
    static_assert(T::size_is_constant);
    assert(start <
           buf.size()); // TODO need macros for various categories of asserts!!!
    if (start + sizeof(p) > buf.size())
    {
        return RetStat::ERROR_BUFFER_TOO_SMALL;
    }
    endian_host_spdm_copy(*reinterpret_cast<const T*>(&buf[start]), p);
    start += sizeof(T);
    return RetStat::OK;
}

template <typename T, typename... Targs>
[[nodiscard]] RetStat packet_decode(T& p, const std::vector<uint8_t>& buf,
                                    size_t& off, Targs... fargs)
{
    if (off + sizeof(packet_message_header) > buf.size())
    {
        return RetStat::ERROR_BUFFER_TOO_SMALL;
    }
    if (packet_message_header_get_requestresponsecode(&buf[off]) !=
        T::RequestResponseCode)
    {
        return RetStat::ERROR_WRONG_REQUEST_RESPONSE_CODE;
    }
    auto rs = packet_decode_internal(p, buf, off, fargs...);
    if (is_error(rs))
    {
        return rs;
    }
    if (off < buf.size())
    {
        return RetStat::WARNING_BUFFER_TOO_BIG;
    }
    return rs;
}

template <typename T>
void packet_encode_basic(const T& p, uint8_t* buf)
{
    endian_host_spdm_copy(p, *reinterpret_cast<T*>(buf));
}
template <typename T>
void packet_encode_basic(const T& p, std::vector<uint8_t>& buf, size_t& start)
{
    static_assert(std::is_integral<T>::value || std::is_enum<T>::value);
    if (buf.size() < start + sizeof(p))
    {
        buf.resize(start + sizeof(p));
    }
    packet_encode_basic(p, &buf[start]);
    start += sizeof(T);
}
template <typename T>
[[nodiscard]] RetStat
    packet_encode_internal(const T& p, std::vector<uint8_t>& buf, size_t& start)
{
    static_assert(T::size_is_constant);
    if (buf.size() < start + sizeof(p))
    {
        buf.resize(start + sizeof(p));
    }
    packet_encode_basic(p, &buf[start]);
    start += sizeof(T);
    return RetStat::OK;
}

template <typename T>
[[nodiscard]] RetStat packet_encode(const T& p, std::vector<uint8_t>& buf,
                                    size_t start = 0)
{
    auto rs = packet_encode_internal(p, buf, start);
    if (is_error(rs))
    {
        return rs;
    }
    if (start + sizeof(p) < buf.size())
    {
        return RetStat::WARNING_BUFFER_TOO_BIG;
    }
    return rs;
}

// helpers for simple byte chunks
[[nodiscard]] inline RetStat
    packet_decode_basic(uint8_t* dst, size_t size,
                        const std::vector<uint8_t>& buf, size_t& start)
{
    //	assert(start < buf.size());//TODO need macros for various categories of
    // asserts!!!
    if (start + size > buf.size())
    {
        return RetStat::ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(dst, &buf[start], size);
    start += size;
    return RetStat::OK;
}
[[nodiscard]] inline RetStat
    packet_decode_basic(std::vector<uint8_t>& dst,
                        const std::vector<uint8_t>& buf, size_t& start)
{
    return packet_decode_basic(dst.data(), dst.size(), buf, start);
}
template <size_t N>
[[nodiscard]] RetStat packet_decode_basic(uint8_t (&dst)[N],
                                          const std::vector<uint8_t>& buf,
                                          size_t& start)
{
    return packet_decode_basic(dst, N, buf, start);
}
