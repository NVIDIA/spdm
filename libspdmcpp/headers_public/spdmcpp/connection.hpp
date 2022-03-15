
#pragma once

#include "common.hpp"
#include "hash.hpp"

#include <mbedtls/md.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

#include <array>
#include <bitset>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>
#include <map>
#include <vector>

namespace spdmcpp
{
// TODO implement warnings and global (maybe granular?) warning policies!?
//  and/or error policies as well, although those would have to be much more
//  specific I imagine...

/*
class FlowClass
{
  public:
    FlowClass(ConnectionClass* con) : Connection(con)
    {}
    virtual ~FlowClass() = 0;

    virtual RetStat handle_send() = 0;
    virtual RetStat handle_recv(std::vector<uint8_t>& buf) = 0;

  protected:
    ConnectionClass* Connection = nullptr;
};

class QueryFlowClass : public FlowClass
{
  public:
    QueryFlowClass(ConnectionClass* con) : FlowClass(con)
    {}

    enum StateEnum
    {
        STATE_START,
        STATE_GOT_VERSION,
        STATE_GOT_CAPABILITIES,
        STATE_GOT_ALGORITHMS,
        STATE_GOT_DIGEST,
        STATE_END,
    };

    RetStat handle_send();
    RetStat handle_recv(std::vector<uint8_t>& buf);

  private:
    StateEnum State = STATE_START;
};*/

class TimingClass
{
  public:
    timeout_ms_t getT1() const
    {
        return RTT + ST1;
    }
    timeout_ms_t getT2() const
    {
        return RTT + CT;
    }

    void setCTExponent(uint8_t ctexp)
    {
        if (ctexp < 10) // 2^10 is < 1024 us, so < 1 ms
        {
            CT = 1;
            return;
        }
        ctexp -= 10;
        if (ctexp >= sizeof(CT) * 8) // exceeds value range cap to max
        {
            CT = TIMEOUT_MS_MAXIMUM;
            return;
        }
        CT = static_cast<timeout_ms_t>(1) << ctexp;
        // TODO add the extra missing bit due to dividing by 1024 instead of
        // 1000;
    }

  private:
    timeout_ms_t RTT = 3000; // round-trip transport implementation defined,
                             // TODO likely needs to be CLI configurable?!
                             // openbmc in qemu is extremely slow
    static constexpr timeout_ms_t ST1 = 100;

    timeout_ms_t T1 = 0;

    timeout_ms_t CT = 0;
    timeout_ms_t T2 = 0;
};

class ConnectionClass
{
    // TODO this has become extremely spaghetti (not enough time to do better,
    // and spdm spec is very stateful...),byl worth trying to refactor
  public:
    typedef uint8_t SlotIdx;
    static constexpr SlotIdx SLOT_NUM = 8;

    ConnectionClass(ContextClass* context) : Context(context), Log(std::cout)
    {}
    ~ConnectionClass()
    {}

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

    RetStat init_connection();
    RetStat refresh_measurements(SlotIdx slotidx);
    RetStat refresh_measurements(SlotIdx slotidx, const nonce_array_32& nonce);
    RetStat refresh_measurements(SlotIdx slotidx,
                                 const std::bitset<256>& measurement_indices);
    RetStat refresh_measurements(SlotIdx slotidx, const nonce_array_32& nonce,
                                 const std::bitset<256>& measurement_indices);
    void reset_connection();

    SlotIdx GetCurrentCertificateSlotIdx() const
    {
        return CertificateSlotIdx;
    }

    bool HasInfo(ConnectionInfoEnum info) const
    {
        return !!(GotInfo &
                  (1 << static_cast<std::underlying_type_t<ConnectionInfoEnum>>(
                       info)));
    }

    bool SlotHasInfo(SlotIdx slotidx, SlotInfoEnum info) const
    {
        assert(slotidx < SLOT_NUM);
        return !!(
            Slots[slotidx].GotInfo &
            (1 << static_cast<std::underlying_type_t<SlotInfoEnum>>(info)));
    }

    [[nodiscard]] RetStat try_get_version();
    [[nodiscard]] RetStat try_get_capabilities();
    [[nodiscard]] RetStat try_negotiate_algorithms();
    [[nodiscard]] RetStat try_get_digest();
    [[nodiscard]] RetStat try_get_certificate(SlotIdx idx);
    [[nodiscard]] RetStat try_get_certificate_chunk(SlotIdx idx);
    [[nodiscard]] RetStat try_get_measurements();
    [[nodiscard]] RetStat try_get_measurements(uint8_t idx);

    [[nodiscard]] RetStat try_challenge();

    template <class T>
    [[nodiscard]] RetStat handle_recv();

    [[nodiscard]] RetStat handle_recv();
    [[nodiscard]] RetStat handle_timeout();

    bool is_waiting_for_response() const
    {
        return WaitingForResponse != RequestResponseEnum::INVALID;
    }

    HashEnum getSignatureHash() const
    {
        assert(HasInfo(ConnectionInfoEnum::ALGORITHMS));
        return to_hash(Algorithms.Min.BaseHashAlgo);
    }
    HashEnum getMeasurementHash() const
    {
        assert(HasInfo(ConnectionInfoEnum::ALGORITHMS));
        return to_hash(Algorithms.Min.MeasurementHashAlgo);
    }
    MessageVersionEnum getMessageVersion() const
    {
        assert(HasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));
        return MessageVersion;
    }
    bool getCertificatesDER(std::vector<uint8_t>& buf, SlotIdx slotidx) const;
    //     bool getCertificatesPEM(std::string& str, SlotIdx slotidx) const;

    typedef std::map<uint8_t, packet_measurement_field_var>
        DMTFMeasurementsContainer;
    const DMTFMeasurementsContainer& getDMTFMeasurements(SlotIdx slotidx) const
    {
        assert(slotidx < SLOT_NUM);
        assert(SlotHasInfo(slotidx, SlotInfoEnum::MEASUREMENTS));
        return Slots[slotidx].DMTFMeasurements;
    }
    const std::vector<uint8_t>& getSignedMeasurementsBuffer() const
    {
        return RefBuf(BufEnum::L);
    }
    const nonce_array_32& getMeasurementNonce() const
    {
        return MeasurementNonce;
    }

    std::vector<uint8_t>& getResponseBufferRef()
    {
        return ResponseBuffer;
    }

    LogClass& getLog()
    {
        return Log;
    }

  protected:
    enum class BufEnum : uint8_t
    {
        M_START,
        A = M_START,
        B,
        C,
        M_END = C,
        L,
        NUM,
    };

    struct SlotClass
    {
        std::vector<uint8_t> Digest;
        std::vector<uint8_t> Certificates; // TODO should unnecessary in the en
        std::vector<mbedtls_x509_crt*>
            MCertificates; // TODO should be abstracted in the end

        DMTFMeasurementsContainer DMTFMeasurements;

        size_t CertificateOffset =
            0; // offset into Certificates[] where the DER data starts

        uint8_t GotInfo = 0;
        static_assert(sizeof(GotInfo) * 8 >=
                      static_cast<std::underlying_type_t<SlotInfoEnum>>(
                          SlotInfoEnum::NUM));

        void MarkInfo(SlotInfoEnum info)
        {
            GotInfo |=
                1 << static_cast<std::underlying_type_t<SlotInfoEnum>>(info);
        }

        mbedtls_x509_crt* GetRootCert() const
        {
            // assert(MCertificates.size() >= 2);
            if (MCertificates.empty())
            {
                return nullptr;
            }
            return MCertificates[0];
        }
        mbedtls_x509_crt* GetLeafCert() const
        {
            // assert(MCertificates.size() >= 2);
            if (MCertificates.empty())
            {
                return nullptr;
            }
            return MCertificates[MCertificates.size() - 1];
        }

        void clear()
        {
            GotInfo = 0;
            CertificateOffset = 0;

            Digest.clear();
            Certificates.clear();

            for (auto cert : MCertificates)
                mbedtls_x509_crt_free(cert);
            MCertificates.clear();

            DMTFMeasurements.clear();
        }
    };

    RetStat refresh_measurements_internal();

    template <typename T>
    RetStat send_request(const T& packet, BufEnum bufidx = BufEnum::NUM);
    template <typename T, typename... Targs>
    RetStat interpret_response(T& packet, Targs... fargs);

    template <typename T>
    RetStat async_response();
    template <typename T, typename R>
    RetStat send_request_setup_response(
        const T& request, const R& response, BufEnum bufidx = BufEnum::NUM,
        timeout_ms_t timeout = TIMEOUT_MS_INFINITE, uint16_t retry = 4);

    void clear_timeout();

    std::vector<uint8_t> SendBuffer;
    timeout_ms_t SendTimeout = 0;
    uint16_t SendRetry = 0;

    std::vector<uint8_t> ResponseBuffer;
    size_t ResponseBufferSPDMOffset;

    ContextClass* Context = nullptr;
    TransportClass* Transport = nullptr;
    mutable LogClass Log;

    std::vector<packet_version_number> SupportedVersions;
    MessageVersionEnum MessageVersion = MessageVersionEnum::UNKNOWN;

    packet_algorithms_response_var Algorithms;
    SlotClass Slots[SLOT_NUM];

    TimingClass Timings;

    // TODO the requirement of hashing messages before the hash function is
    // decided by the responder is quite troublesome, probably easiest to
    // calculate all supported hashes in parallel?
    // TODO test perf/memory and decide if we'll use Buffers or running hashes,
    // or a mixture
    HashClass HashM1M2;
    // HashClass HashL1L2;
    std::vector<uint8_t> Bufs[static_cast<size_t>(BufEnum::NUM)];
    std::vector<uint8_t>& RefBuf(BufEnum bufidx)
    {
        return Bufs[static_cast<std::underlying_type_t<BufEnum>>(bufidx)];
    }
    const std::vector<uint8_t>& RefBuf(BufEnum bufidx) const
    {
        return Bufs[static_cast<std::underlying_type_t<BufEnum>>(bufidx)];
    }
    void HashBuf(std::vector<uint8_t>& hash, HashEnum hashtype, BufEnum bufidx)
    {
        HashClass::compute(hash, hashtype, RefBuf(bufidx));
    }

    void AppendToBuf(BufEnum bufidx, uint8_t* data, size_t size)
    {
        HashM1M2.update(data, size);
        std::vector<uint8_t>& buf = RefBuf(bufidx);
        size_t off = buf.size();
        buf.resize(off + size);
        memcpy(&buf[off], data, size);
    }
    void AppendRecvToBuf(BufEnum bufidx)
    {
        AppendToBuf(bufidx, &ResponseBuffer[ResponseBufferSPDMOffset],
                    ResponseBuffer.size() - ResponseBufferSPDMOffset);
    }
    void HashRecv(HashClass& hash)
    {
        hash.update(&ResponseBuffer[ResponseBufferSPDMOffset],
                    ResponseBuffer.size() - ResponseBufferSPDMOffset);
    }

    packet_decode_info PacketDecodeInfo;

    nonce_array_32 MeasurementNonce;
    std::bitset<256> MeasurementIndices;
    SlotIdx CertificateSlotIdx = SLOT_NUM;

    RequestResponseEnum WaitingForResponse = RequestResponseEnum::INVALID;
    uint8_t GotInfo = 0;
    static_assert(sizeof(GotInfo) * 8 >=
                  static_cast<std::underlying_type_t<ConnectionInfoEnum>>(
                      ConnectionInfoEnum::NUM));

    void MarkInfo(ConnectionInfoEnum info)
    {
        GotInfo |=
            1 << static_cast<std::underlying_type_t<ConnectionInfoEnum>>(info);
    }

    uint8_t GetFirstMeasurementIndex() const
    {
        assert(MeasurementIndices.any());
        for (uint8_t i = 0; i < MeasurementIndices.size(); ++i)
        {
            if (MeasurementIndices[i])
                return i;
        }
        // std::unreachable();
        return 255;
    }

    RetStat choose_version();
};

} // namespace spdmcpp
