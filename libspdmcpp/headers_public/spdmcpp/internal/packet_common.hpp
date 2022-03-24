
#include "../packet.hpp"

#pragma once

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
    // TODO maybe we should require a finalize() function and always do
    // p.finalize() here for safety?
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
inline void packet_encode_basic(const uint8_t* src, size_t size,
                                std::vector<uint8_t>& buf, size_t& start)
{
    if (buf.size() < start + size)
    {
        buf.resize(start + size);
    }
    memcpy(&buf[start], src, size);
    start += size;
}
inline void packet_encode_basic(const std::vector<uint8_t>& src,
                                std::vector<uint8_t>& buf, size_t& start)
{
    packet_encode_basic(src.data(), src.size(), buf, start);
}
template <size_t N>
inline void packet_encode_basic(const uint8_t (&src)[N],
                                std::vector<uint8_t>& buf, size_t& start)
{
    packet_encode_basic(src, N, buf, start);
}

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
