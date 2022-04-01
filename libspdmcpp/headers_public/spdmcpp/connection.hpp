
#pragma once

#include "common.hpp"
#include "context.hpp"
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
    virtual RetStat handleRecv(std::vector<uint8_t>& buf) = 0;

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
    RetStat handleRecv(std::vector<uint8_t>& buf);

  private:
    StateEnum State = STATE_START;
};*/

class TimingClass
{
  public:
    timeout_ms_t getT1() const
    {
        return RTT + sT1;
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
    static constexpr timeout_ms_t sT1 = 100;

    timeout_ms_t CT = 0;
};

class ConnectionClass
{
    // TODO this has become extremely spaghetti (not enough time to do better,
    // and spdm spec is very stateful...),byl worth trying to refactor
  public:
    typedef uint8_t SlotIdx;
    static constexpr SlotIdx slotNum = 8;

    ConnectionClass(ContextClass* context) : Context(context), Log(std::cout)
    {}
    ~ConnectionClass()
    {}

    void registerTransport(TransportClass* transport)
    {
        assert(!Transport);
        Transport = transport;
    }
    void unregisterTransport(TransportClass* transport)
    {
        assert(Transport == transport);
        Transport = nullptr;
    }

    RetStat initConnection();
    RetStat refreshMeasurements(SlotIdx slotidx);
    RetStat refreshMeasurements(SlotIdx slotidx, const nonce_array_32& nonce);
    RetStat refreshMeasurements(SlotIdx slotidx,
                                const std::bitset<256>& measurementIndices);
    RetStat refreshMeasurements(SlotIdx slotidx, const nonce_array_32& nonce,
                                const std::bitset<256>& measurementIndices);
    void resetConnection();

    SlotIdx getCurrentCertificateSlotIdx() const
    {
        return CertificateSlotIdx;
    }

    bool hasInfo(ConnectionInfoEnum info) const
    {
        return !!(GotInfo &
                  (1 << static_cast<std::underlying_type_t<ConnectionInfoEnum>>(
                       info)));
    }

    bool slothasInfo(SlotIdx slotidx, SlotInfoEnum info) const
    {
        assert(slotidx < slotNum);
        return !!(
            Slots[slotidx].GotInfo &
            (1 << static_cast<std::underlying_type_t<SlotInfoEnum>>(info)));
    }

    [[nodiscard]] RetStat tryGetVersion();
    [[nodiscard]] RetStat tryGetCapabilities();
    [[nodiscard]] RetStat tryNegotiateAlgorithms();
    [[nodiscard]] RetStat tryGetDigest();
    [[nodiscard]] RetStat tryGetCertificate(SlotIdx idx);
    [[nodiscard]] RetStat tryGetCertificateChunk(SlotIdx idx);
    [[nodiscard]] RetStat tryGetMeasurements();
    [[nodiscard]] RetStat tryGetMeasurements(uint8_t idx);

    [[nodiscard]] RetStat tryChallenge();

    template <class T>
    [[nodiscard]] RetStat handleRecv();

    [[nodiscard]] RetStat handleRecv();
    [[nodiscard]] RetStat handleTimeout();

    bool isWaitingForResponse() const
    {
        return WaitingForResponse != RequestResponseEnum::INVALID;
    }

    HashEnum getSignatureHash() const
    {
        assert(hasInfo(ConnectionInfoEnum::ALGORITHMS));
        return toHash(Algorithms.Min.BaseHashAlgo);
    }
    HashEnum getMeasurementHash() const
    {
        assert(hasInfo(ConnectionInfoEnum::ALGORITHMS));
        return toHash(Algorithms.Min.MeasurementHashAlgo);
    }
    MessageVersionEnum getMessageVersion() const
    {
        assert(hasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));
        return MessageVersion;
    }
    bool getCertificatesDER(std::vector<uint8_t>& buf, SlotIdx slotidx) const;
    //     bool getCertificatesPEM(std::string& str, SlotIdx slotidx) const;

    typedef std::map<uint8_t, PacketMeasurementFieldVar>
        DMTFMeasurementsContainer;
    const DMTFMeasurementsContainer& getDMTFMeasurements() const
    {
        return DMTFMeasurements;
    }
    const std::vector<uint8_t>& getSignedMeasurementsBuffer()
        const // TODO this may no longer be necessary and we could yet again
              // switch back to a running Hash
    {
        return refBuf(BufEnum::L);
    }
    const std::vector<uint8_t>& getSignedMeasurementsHash() const
    {
        return MeasurementsHash;
    }
    const std::vector<uint8_t>& getMeasurementsSignature() const
    {
        return MeasurementsSignature;
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

        size_t CertificateOffset =
            0; // offset into Certificates[] where the DER data starts

        uint8_t GotInfo = 0;
        static_assert(sizeof(GotInfo) * 8 >=
                      static_cast<std::underlying_type_t<SlotInfoEnum>>(
                          SlotInfoEnum::NUM));

        void markInfo(SlotInfoEnum info)
        {
            GotInfo |=
                1 << static_cast<std::underlying_type_t<SlotInfoEnum>>(info);
        }

        mbedtls_x509_crt* getRootCert() const
        {
            // assert(MCertificates.size() >= 2);
            if (MCertificates.empty())
            {
                return nullptr;
            }
            return MCertificates[0];
        }
        mbedtls_x509_crt* getLeafCert() const
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
            {
                mbedtls_x509_crt_free(cert);
            }
            MCertificates.clear();
        }
    };

    RetStat refreshMeasurementsInternal();

    template <typename T>
    RetStat sendRequest(const T& packet, BufEnum bufidx = BufEnum::NUM);
    template <typename T, typename... Targs>
    RetStat interpretResponse(T& packet, Targs... fargs);

    template <typename T>
    RetStat asyncResponse();
    template <typename T, typename R>
    RetStat sendRequestSetupResponse(const T& request, const R& response,
                                     BufEnum bufidx = BufEnum::NUM,
                                     timeout_ms_t timeout = TIMEOUT_MS_INFINITE,
                                     uint16_t retry = 4);

    void clearTimeout();

    std::vector<uint8_t> SendBuffer;
    timeout_ms_t SendTimeout = 0;
    uint16_t SendRetry = 0;

    std::vector<uint8_t> ResponseBuffer;
    size_t ResponseBufferSPDMOffset;

    ContextClass* Context = nullptr;
    TransportClass* Transport = nullptr;
    mutable LogClass Log;

    std::vector<PacketVersionNumber> SupportedVersions;
    MessageVersionEnum MessageVersion = MessageVersionEnum::UNKNOWN;

    PacketAlgorithmsResponseVar Algorithms;
    SlotClass Slots[slotNum];

    TimingClass Timings;

    // TODO the requirement of hashing messages before the hash function is
    // decided by the responder is quite troublesome, probably easiest to
    // calculate all supported hashes in parallel?
    // TODO test perf/memory and decide if we'll use Buffers or running hashes,
    // or a mixture
    // HashClass HashM1M2;
    // HashClass HashL1L2;
    std::vector<uint8_t> Bufs[static_cast<size_t>(BufEnum::NUM)];
    std::vector<uint8_t>& refBuf(BufEnum bufidx)
    {
        return Bufs[static_cast<std::underlying_type_t<BufEnum>>(bufidx)];
    }
    const std::vector<uint8_t>& refBuf(BufEnum bufidx) const
    {
        return Bufs[static_cast<std::underlying_type_t<BufEnum>>(bufidx)];
    }
    void hashBuf(std::vector<uint8_t>& hash, HashEnum hashtype, BufEnum bufidx)
    {
        HashClass::compute(hash, hashtype, refBuf(bufidx));
    }

    void appendToBuf(BufEnum bufidx, uint8_t* data, size_t size)
    {
        // HashM1M2.update(data, size);
        std::vector<uint8_t>& buf = refBuf(bufidx);
        size_t off = buf.size();
        buf.resize(off + size);
        memcpy(&buf[off], data, size);
    }
    void appendRecvToBuf(BufEnum bufidx)
    {
        appendToBuf(bufidx, &ResponseBuffer[ResponseBufferSPDMOffset],
                    ResponseBuffer.size() - ResponseBufferSPDMOffset);
    }
    void hashRecv(HashClass& hash)
    {
        hash.update(&ResponseBuffer[ResponseBufferSPDMOffset],
                    ResponseBuffer.size() - ResponseBufferSPDMOffset);
    }

    PacketDecodeInfo packetDecodeInfo;

    DMTFMeasurementsContainer DMTFMeasurements;
    std::vector<uint8_t> MeasurementsHash;
    std::vector<uint8_t> MeasurementsSignature;
    nonce_array_32 MeasurementNonce;
    std::bitset<256> MeasurementIndices;
    SlotIdx CertificateSlotIdx = slotNum;

    RequestResponseEnum WaitingForResponse = RequestResponseEnum::INVALID;
    uint8_t GotInfo = 0;
    static_assert(sizeof(GotInfo) * 8 >=
                  static_cast<std::underlying_type_t<ConnectionInfoEnum>>(
                      ConnectionInfoEnum::NUM));

    void markInfo(ConnectionInfoEnum info)
    {
        GotInfo |=
            1 << static_cast<std::underlying_type_t<ConnectionInfoEnum>>(info);
    }

    uint8_t getFirstMeasurementIndex() const
    {
        assert(MeasurementIndices.any());
        for (uint8_t i = 0; i < MeasurementIndices.size(); ++i)
        {
            if (MeasurementIndices[i])
            {
                return i;
            }
        }
        // std::unreachable();
        return 255;
    }

    RetStat chooseVersion();
};

} // namespace spdmcpp
