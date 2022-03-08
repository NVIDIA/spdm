
#include <spdmcpp/helpers.hpp>
#include <spdmcpp/packet.hpp>

#include <array>
#include <cstring>
#include <random>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace spdmcpp;

#define SPDMCPP_TEST_ASSERT_RS(rs, val)                                        \
    do                                                                         \
    {                                                                          \
        if ((rs) != (val))                                                     \
        {                                                                      \
            std::cerr << "Unexpected: " #rs " = " << get_cstr(rs)              \
                      << std::endl;                                            \
            std::cerr << " in: " << __func__ << "() @ " << __FILE__ << " : "   \
                      << std::dec << __LINE__ << std::endl;                    \
            return false;                                                      \
        }                                                                      \
    } while (false)

void print(const std::vector<uint8_t>& buf)
{
    for (size_t i = 0; i < buf.size(); ++i)
    {
        if (i)
            std::cerr << " 0x";
        else
            std::cerr << "0x";
        std::cerr << std::hex << (int)buf[i];
    }
}

template <typename T>
inline void fill_pseudorandom_packet(
    T& p, std::mt19937::result_type seed = mt19937_default_seed)
{
    static_assert(T::size_is_constant);
    fill_pseudorandom_type(p, seed);
    packet_message_header_set_requestresponsecode(
        reinterpret_cast<uint8_t*>(&p), T::RequestResponseCode);
}

template <typename T>
inline T return_pseudorandom_packet(
    std::mt19937::result_type seed = mt19937_default_seed)
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
        if (off != src.size())
        {
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
    if (!std::equal(src.begin(), src.end(), dst.begin()))
    {
        std::cerr << "src != dst";
        return false;
    }
    return true;
}

template <class T>
bool packet_pseudorandom_decode_encode()
{
    LogClass log(std::cerr);
    static_assert(T::size_is_constant);
    std::vector<uint8_t> src, dst;
    src.resize(sizeof(T));
    fill_pseudorandom(src);

    packet_message_header_set_requestresponsecode(src.data(),
                                                  T::RequestResponseCode);

    std::cerr << "src: ";
    print(src);
    std::cerr << std::endl;

    T packet;
    {
        size_t off = 0;
        auto rs = packet_decode(packet, src, off);
        SPDMCPP_TEST_ASSERT_RS(rs, RetStat::OK);
        assert(off == src.size());
    }
    packet.print_ml(log);
    {
        auto rs = packet_encode(packet, dst);
        SPDMCPP_TEST_ASSERT_RS(rs, RetStat::OK);
    }
    std::cerr << "dst: ";
    print(dst);
    std::cerr << std::endl;
    if (!std::equal(src.begin(), src.end(), dst.begin()))
    {
        std::cerr << "src != dst";
        return false;
    }

    src.push_back(0xBA);
    {
        size_t off = 0;
        auto rs = packet_decode(packet, src, off);
        SPDMCPP_TEST_ASSERT_RS(rs, RetStat::WARNING_BUFFER_TOO_BIG);
    }
    src.pop_back();
    src.pop_back();
    {
        size_t off = 0;
        auto rs = packet_decode(packet, src, off);
        SPDMCPP_TEST_ASSERT_RS(rs, RetStat::ERROR_BUFFER_TOO_SMALL);
    }
    return true;
}

template <class T, typename... Targs>
bool packet_encode_decode(const T& src, Targs... fargs)
{
    LogClass log(std::cerr);
    log.iprintln("src:");
    src.print_ml(log);

    std::vector<uint8_t> buf;
    {
        auto rs = packet_encode(src, buf);
        if (rs != RetStat::OK)
        {
            std::cerr << "RetStat: " << get_cstr(rs) << std::endl;
            return false;
        }
    }
    print(buf);
    std::cerr << std::endl;
    T dst;
    {
        size_t off = 0;
        auto rs = packet_decode(dst, buf, off, fargs...);
        if (rs != RetStat::OK)
        {
            std::cerr << "RetStat: " << get_cstr(rs) << std::endl;
            return false;
        }
        if (off != buf.size())
        {
            std::cerr << "invalid final offset: " << off
                      << " compared to buf.size(): " << buf.size() << std::endl;
            return false;
        }
    }
    log.iprintln("dst:");
    dst.print_ml(log);
    std::cerr << std::endl;
    return src == dst; // TODO ?!
    return true;
}

template <class T, typename... Targs>
bool packet_encode_decode_internal(const T& src, Targs... fargs)
{
    LogClass log(std::cerr);
    log.iprintln("src:");
    src.print_ml(log);

    std::vector<uint8_t> buf;
    {
        size_t off = 0;
        auto rs = packet_encode_internal(src, buf, off);
        if (rs != RetStat::OK)
        {
            std::cerr << "RetStat: " << get_cstr(rs) << std::endl;
            return false;
        }
    }
    print(buf);
    std::cerr << std::endl;
    T dst;
    {
        size_t off = 0;
        auto rs = packet_decode_internal(dst, buf, off, fargs...);
        if (rs != RetStat::OK)
        {
            std::cerr << "RetStat: " << get_cstr(rs) << std::endl;
            return false;
        }
        if (off != buf.size())
        {
            std::cerr << "invalid final offset: " << off
                      << " compared to buf.size(): " << buf.size() << std::endl;
            return false;
        }
    }
    log.iprintln("dst:");
    dst.print_ml(log);
    std::cerr << std::endl;
    return src == dst; // TODO ?!
    return true;
}

TEST(packet_pseudorandom_decode_encode, static_size)
{
    EXPECT_TRUE(
        packet_pseudorandom_decode_encode_basic<packet_message_header>());
    EXPECT_TRUE(
        packet_pseudorandom_decode_encode_basic<packet_version_number>());
    EXPECT_TRUE(
        packet_pseudorandom_decode_encode_basic<packet_error_response_min>());
    EXPECT_TRUE(
        packet_pseudorandom_decode_encode_basic<packet_certificate_chain>());
    EXPECT_TRUE(packet_pseudorandom_decode_encode_basic<
                packet_measurement_block_min>());

    EXPECT_TRUE(
        packet_pseudorandom_decode_encode<packet_version_response_min>());
    EXPECT_TRUE(
        packet_pseudorandom_decode_encode<packet_get_capabilities_request>());
    EXPECT_TRUE(
        packet_pseudorandom_decode_encode<packet_capabilities_response>());
    EXPECT_TRUE(packet_pseudorandom_decode_encode<
                packet_negotiate_algorithms_request_min>());
    EXPECT_TRUE(
        packet_pseudorandom_decode_encode<packet_algorithms_response_min>());
    EXPECT_TRUE(
        packet_pseudorandom_decode_encode<packet_get_digests_request>());
    EXPECT_TRUE(
        packet_pseudorandom_decode_encode<packet_digests_response_min>());
    EXPECT_TRUE(
        packet_pseudorandom_decode_encode<packet_get_certificate_request>());
    EXPECT_TRUE(
        packet_pseudorandom_decode_encode<packet_certificate_response_min>());
    EXPECT_TRUE(packet_pseudorandom_decode_encode<packet_challenge_request>());
    EXPECT_TRUE(packet_pseudorandom_decode_encode<
                packet_challenge_auth_response_min>());

    EXPECT_TRUE(packet_pseudorandom_decode_encode<
                packet_get_measurements_request_min>());
    EXPECT_TRUE(
        packet_pseudorandom_decode_encode<packet_measurements_response_min>());
}

TEST(packet_pseudorandom_encode_decode, packet_error_response_var)
{
    packet_error_response_var p;
    fill_pseudorandom_packet(p.Min);
    //     p.VersionNumberEntries.push_back(
    //         return_pseudorandom_type<packet_version_number>());
    //     p.VersionNumberEntries.push_back(
    //         return_pseudorandom_type<packet_version_number>());
    EXPECT_TRUE(packet_encode_decode(p));
}

TEST(packet_pseudorandom_encode_decode, packet_version_response_var)
{
    packet_version_response_var p;
    fill_pseudorandom_packet(p.Min);
    p.VersionNumberEntries.push_back(
        return_pseudorandom_type<packet_version_number>());
    p.VersionNumberEntries.push_back(
        return_pseudorandom_type<packet_version_number>());
    EXPECT_TRUE(packet_encode_decode(p));
}

TEST(packet_pseudorandom_encode_decode, packet_negotiate_algorithms_request_var)
{
    packet_negotiate_algorithms_request_var p;
    fill_pseudorandom_packet(p.Min);

    p.PacketReqAlgVector.push_back(
        PacketReqAlgStruct::buildSupported2(AlgTypeEnum::DHE, 0x1b, 0x00));
    p.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildSupported2(
        AlgTypeEnum::AEADCipherSuite, 0x06, 0x00));
    p.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildSupported2(
        AlgTypeEnum::ReqBaseAsymAlg, 0x0F, 0x00));
    p.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildSupported2(
        AlgTypeEnum::KeySchedule, 0x01, 0x00));

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packet_encode_decode(p));
}

TEST(packet_pseudorandom_encode_decode, packet_algorithms_response_var)
{
    packet_algorithms_response_var p;
    fill_pseudorandom_packet(p.Min);

    p.PacketReqAlgVector.push_back(
        PacketReqAlgStruct::buildSupported2(AlgTypeEnum::DHE, 0x1b, 0x00));
    p.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildSupported2(
        AlgTypeEnum::AEADCipherSuite, 0x06, 0x00));
    p.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildSupported2(
        AlgTypeEnum::ReqBaseAsymAlg, 0x0F, 0x00));
    p.PacketReqAlgVector.push_back(PacketReqAlgStruct::buildSupported2(
        AlgTypeEnum::KeySchedule, 0x01, 0x00));

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packet_encode_decode(p));
}

TEST(packet_pseudorandom_encode_decode, packet_digests_response_var)
{
    packet_decode_info info;
    info.BaseHashSize = 32;

    packet_digests_response_var p;

    fill_pseudorandom_packet(p.Min);

    p.Digests[0].resize(info.BaseHashSize);
    fill_pseudorandom(p.Digests[0]);

    p.Digests[1].resize(info.BaseHashSize);
    fill_pseudorandom(p.Digests[1]);

    p.Digests[7].resize(info.BaseHashSize);
    fill_pseudorandom(p.Digests[7]);

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packet_encode_decode(p, info));
}

TEST(packet_pseudorandom_encode_decode, packet_certificate_response_var)
{
    packet_certificate_response_var p;

    fill_pseudorandom_packet(p.Min);

    p.CertificateVector.resize(1023);
    fill_pseudorandom(p.CertificateVector);

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packet_encode_decode(p));
}

TEST(packet_pseudorandom_encode_decode, packet_challenge_auth_response_var)
{
    packet_decode_info info;
    info.ChallengeParam2 = 0;
    info.BaseHashSize = 32;
    info.SignatureSize = 48;

    packet_challenge_auth_response_var p;

    fill_pseudorandom_packet(p.Min);

    p.CertChainHashVector.resize(info.BaseHashSize);
    fill_pseudorandom(p.CertChainHashVector);

    fill_pseudorandom(p.Nonce);

    p.OpaqueDataVector.resize(127);
    fill_pseudorandom(p.OpaqueDataVector);

    p.SignatureVector.resize(info.SignatureSize);
    fill_pseudorandom(p.SignatureVector);

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packet_encode_decode(p, info));
}

TEST(packet_pseudorandom_encode_decode, packet_challenge_auth_response_var_1)
{
    packet_decode_info info;
    info.ChallengeParam2 = 1;
    info.BaseHashSize = 32;
    info.SignatureSize = 48;

    packet_challenge_auth_response_var p;

    fill_pseudorandom_packet(p.Min);

    p.CertChainHashVector.resize(info.BaseHashSize);
    fill_pseudorandom(p.CertChainHashVector);

    fill_pseudorandom(p.Nonce);

    p.MeasurementSummaryHashVector.resize(info.BaseHashSize);
    fill_pseudorandom(p.MeasurementSummaryHashVector);

    p.OpaqueDataVector.resize(127);
    fill_pseudorandom(p.OpaqueDataVector);

    p.SignatureVector.resize(info.SignatureSize);
    fill_pseudorandom(p.SignatureVector);

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packet_encode_decode(p, info));
}

TEST(packet_pseudorandom_encode_decode, packet_get_measurements_request_var)
{
    packet_get_measurements_request_var p;

    fill_pseudorandom_packet(p.Min);

    p.Min.Header.Param1 = 0; // need to clear to test lack of Nonce
    // fill_pseudorandom(p.Nonce);
    // p.SlotIDParam = 1;

    //     EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packet_encode_decode(p));
}

TEST(packet_pseudorandom_encode_decode, packet_get_measurements_request_var_1)
{
    packet_get_measurements_request_var p;

    fill_pseudorandom_packet(p.Min);

    p.set_nonce();
    fill_pseudorandom(p.Nonce);
    p.SlotIDParam = 1;

    //     EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packet_encode_decode(p));
}

TEST(packet_pseudorandom_encode_decode, packet_measurement_block_var)
{
    packet_measurement_block_var p;

    fill_pseudorandom_type(p.Min);

    p.MeasurementVector.resize(1023);
    fill_pseudorandom(p.MeasurementVector);

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packet_encode_decode_internal(p));
}

TEST(packet_pseudorandom_encode_decode, packet_measurement_field_var)
{
    packet_measurement_field_var p;

    fill_pseudorandom_type(p.Min);

    p.ValueVector.resize(1023);
    fill_pseudorandom(p.ValueVector);

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packet_encode_decode_internal(p));
}

TEST(packet_pseudorandom_encode_decode, packet_measurements_response_var)
{
    packet_decode_info info;
    info.GetMeasurementsParam1 = 0;
    info.BaseHashSize = 32;
    info.SignatureSize = 48;

    packet_measurements_response_var p;

    fill_pseudorandom_packet(p.Min);

    p.OpaqueDataVector.resize(127);
    fill_pseudorandom(p.OpaqueDataVector);

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packet_encode_decode(p, info));
}

TEST(packet_pseudorandom_encode_decode, packet_measurements_response_var_1)
{
    packet_decode_info info;
    info.GetMeasurementsParam1 = 1;
    info.BaseHashSize = 32;
    info.SignatureSize = 48;

    packet_measurements_response_var p;

    fill_pseudorandom_packet(p.Min);

    p.MeasurementBlockVector.resize(3);
    {
        packet_measurement_block_var& b = p.MeasurementBlockVector[0];
        fill_pseudorandom_type(b.Min);
        b.MeasurementVector.resize(1023);
        fill_pseudorandom(b.MeasurementVector);
        EXPECT_EQ(b.finalize(), RetStat::OK);
    }
    {
        packet_measurement_block_var& b = p.MeasurementBlockVector[1];
        fill_pseudorandom_type(b.Min);
        b.MeasurementVector.resize(3);
        fill_pseudorandom(b.MeasurementVector);
        EXPECT_EQ(b.finalize(), RetStat::OK);
    }
    {
        packet_measurement_block_var& b = p.MeasurementBlockVector[2];
        fill_pseudorandom_type(b.Min);
        b.MeasurementVector.resize(107);
        fill_pseudorandom(b.MeasurementVector);
        EXPECT_EQ(b.finalize(), RetStat::OK);
    }

    p.SignatureVector.resize(info.SignatureSize);
    fill_pseudorandom(p.SignatureVector);

    EXPECT_EQ(p.finalize(), RetStat::OK);

    EXPECT_TRUE(packet_encode_decode(p, info));
}
