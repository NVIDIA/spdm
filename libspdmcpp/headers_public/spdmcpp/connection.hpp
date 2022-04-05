
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

/** @class TimingClass
 *  @brief Helper class for calculating timeout periods
 *  @details Timeouts defined by DSP0274_1.1.1 section "9 Timing requirements"
 * page 29
 */
class TimingClass
{
  public:
    /** @brief Function to create ipAddress dbus object.
     *  @param[in] addressType - Type of ip address.
     *  @param[in] ipAddress- IP address.
     *  @param[in] prefixLength - Length of prefix.
     *  @param[in] gateway - Gateway ip address.
     */
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
        if (ctexp >= sizeof(CT) * 8) // exceeds value range, cap to max
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

/** @class ConnectionClass
 *  @brief Class for handling communication with a specific SPDM Responder
 *  @details Currently the core purpose of this class is to perform the
 *           following flows from the DSP0274_1.1.1 spec:
 *           - "10.1 Capability discovery and negotiation" page 32
 *           - "10.5 Responder identity authentication" page 52-58
 *           - "10.10 Firmware and other measurements" page 68-77
 */
class ConnectionClass
{
    // TODO this has become extremely spaghetti (not enough time to do better,
    // and spdm spec is very stateful...),byl worth trying to refactor
  public:
    /** Type alias to distinguish Certificate Slot Indices */
    using SlotIdx = uint8_t;

    /** Constant to define the maximum possible number of slots defined by
     * DSP0274_1.1.1 page 56 */
    static constexpr SlotIdx slotNum = 8;

    /** @brief Main constructor
     *  @param[in] context - Context containing various common configuration and
     * information
     */
    ConnectionClass(ContextClass* context);
    ~ConnectionClass() = default;

    /** @brief Registers a TransportClass for handling the connection (e.g. with
     * standard mtcp-demux-daemon the instance handles encapsulating with the
     * EndpointID)
     *  @param[in] transport - Object to be used for sending/reading messages,
     * ConnectionClass does not take ownership and will not deallocate the
     * object
     */
    void registerTransport(TransportClass* transport)
    {
        assert(!Transport);
        Transport = transport;
    }

    /** @brief Unregisters the TransportClass object, should be called before
     * destroying ConnectionClass
     */
    void unregisterTransport(TransportClass* transport)
    {
        assert(Transport == transport);
        Transport = nullptr;
    }

    /** @brief Begins the default communicatiion with the Responder
     */
    RetStat initConnection();

    /** @brief Function to redo the discovery, authentication, and measurement
     * flow
     *  @param[in] slotIdx - Certificate Slot Index to be used for
     * authentication and measurement signatures
     */
    RetStat refreshMeasurements(SlotIdx slotidx);

    /** @brief Function to redo the discovery, authentication, and measurement
     * flow
     *  @param[in] slotIdx - Certificate Slot Index to be used for
     * authentication and measurement signatures
     *  @param[in] nonce - The nonce that should be embeded in the appropriate
     * field during authentication and measurement DSP0274_1.1.1 page 60 and 70
     */
    RetStat refreshMeasurements(SlotIdx slotidx, const nonce_array_32& nonce);

    /** @brief Function to redo the discovery, authentication, and measurement
     * flow
     *  @param[in] slotIdx - Certificate Slot Index to be used for
     * authentication and measurement signatures
     *  @param[in] measurementIndices - A bitmask of the measurements that
     * should be requested, bit 0 is reserved and invalid, and bit 255 is
     * signifies that all measurements should be requested at once, (if bit 255
     * is set all others should be unset)
     */
    RetStat refreshMeasurements(SlotIdx slotidx,
                                const std::bitset<256>& measurementIndices);

    /** @brief Function to redo the discovery, authentication, and measurement
     * flow
     *  @param[in] slotIdx - Certificate Slot Index to be used for
     * authentication and measurement signatures
     *  @param[in] measurementIndices - A bitmask of the measurements that
     * should be requested, bit 0 is reserved and invalid, and bit 255 is
     * signifies that all measurements should be requested at once, (if bit 255
     * is set all others should be unset)
     *  @param[in] nonce - The nonce that should be embeded in the appropriate
     * field during authentication and measurement DSP0274_1.1.1 page 60 and 70
     */
    RetStat refreshMeasurements(SlotIdx slotidx, const nonce_array_32& nonce,
                                const std::bitset<256>& measurementIndices);

    /** @brief Resets all connection information to a state equivalent to just
     * after constructing ConnectionClass
     */
    void resetConnection();

    /** @brief Gets the Certificate Slot Index that was used during the current
     * and/or last performed communication flow, this is the value that was
     * passed to the refreshMeasurements() function call
     */
    SlotIdx getCurrentCertificateSlotIdx() const
    {
        return CertificateSlotIdx;
    }

    /** @brief Function to query whether the ConnectionClass has received
     * the given information from the responder
     */
    bool hasInfo(ConnectionInfoEnum info) const
    {
        return !!(GotInfo &
                  (1 << static_cast<std::underlying_type_t<ConnectionInfoEnum>>(
                       info)));
    }

    /** @brief Function to query whether the ConnectionClass has received
     * the given information from the responder for a specific Certificate Slot
     */
    bool slothasInfo(SlotIdx slotidx, SlotInfoEnum info) const
    {
        assert(slotidx < slotNum);
        return !!(
            Slots[slotidx].GotInfo &
            (1 << static_cast<std::underlying_type_t<SlotInfoEnum>>(info)));
    }

    /** @brief Function to query whether ConnectionClass is still waiting for
     * some response message from an SPDM Responder
     *  @details After issuing a refreshMeasurement call and passing new
     * messages this function can be used to detect when the communication flow
     * is finished (both successfully or with an error condition)
     */
    bool isWaitingForResponse() const
    {
        return WaitingForResponse != RequestResponseEnum::INVALID;
    }

    /** @brief The hash algorithm used for generating signatures
     */
    HashEnum getSignatureHash() const
    {
        assert(hasInfo(ConnectionInfoEnum::ALGORITHMS));
        return toHash(Algorithms.Min.BaseHashAlgo);
    }
    /** @brief The hash algorithm used for generating measurement digests
     */
    HashEnum getMeasurementHash() const
    {
        assert(hasInfo(ConnectionInfoEnum::ALGORITHMS));
        return toHash(Algorithms.Min.MeasurementHashAlgo);
    }

    /** @brief The SPDM version used during communication
     */
    MessageVersionEnum getMessageVersion() const
    {
        assert(hasInfo(ConnectionInfoEnum::CHOOSEN_VERSION));
        return MessageVersion;
    }

    /** @brief Returns the certificate chain for the given slot index
     *  @details Note this function will return false if the certificate chain
     * was not fetched for the given slot (even if it is available on the device
     * itself)
     *  @param[out] buf - the buffer into which the certificate chain is written
     *  @returns true if the certificate chain was available and written into
     * buf, false otherwise
     */
    bool getCertificatesDER(std::vector<uint8_t>& buf, SlotIdx slotidx) const;

    /** @brief The buffer containing measurements communication, used for
     * computing the L1/L2 hash
     *  @details Contains all the GET_MEASUREMENTS requests and corresponding
     * MEASUREMENTS responses
     */
    using DMTFMeasurementsContainer =
        std::map<uint8_t, PacketMeasurementFieldVar>;
    const DMTFMeasurementsContainer& getDMTFMeasurements() const
    {
        return DMTFMeasurements;
    }
    /** @brief The buffer containing measurements communication, used for
     * computing the L1/L2 hash
     *  @details Contains all the GET_MEASUREMENTS requests and corresponding
     * MEASUREMENTS responses
     */
    const std::vector<uint8_t>& getSignedMeasurementsBuffer() const
    {
        return refBuf(BufEnum::L);
    }
    /** @brief The L1/L2 hash of the measurements, as returned by
     * getSignedMeasurementsBuffer()
     */
    const std::vector<uint8_t>& getSignedMeasurementsHash() const
    {
        return MeasurementsHash;
    }
    /** @brief Signature for getSignedMeasurementsHash() and corresponding to
     * getSignedMeasurementsBuffer()
     *  @details This is the signature generated by the Responder
     */
    const std::vector<uint8_t>& getMeasurementsSignature() const
    {
        return MeasurementsSignature;
    }
    const nonce_array_32& getMeasurementNonce() const
    {
        return MeasurementNonce;
    }

    /** @brief Returns the LogClass used for logging the communication flow and
     * packets
     */
    LogClass& getLog()
    {
        return Log;
    }

    /** @brief This is the buffer that the received response data should be
     * stored in prior to calling handleRecv()
     *  @details TODO this interface is likely quite confusing and should be
     * refactored
     */
    std::vector<uint8_t>& getResponseBufferRef()
    {
        return ResponseBuffer;
    }

    /** @brief Callback for handling incomming packets
     *  @details TODO this interface is likely quite confusing and should be
     * refactored
     */
    [[nodiscard]] RetStat handleRecv();

    /** @brief Callback for handling a timeout event instead of the expected
     * response
     */
    [[nodiscard]] RetStat handleTimeout();

  protected:
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

    /** @brief This enum is used for selecting the buffer for computing the
     * M1/M2 and L1/L2 hash
     *  @details The definitions for A/B/C buffers which are used for the M1/M2
     * hash are defined in DSP0274_1.1.1 pages 64-66. The L buffer is used for
     * the L1/L2 hash, defined in DSP0274_1.1.1 pages 73-75
     */
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

    /** @struct SlotClass
     *  @brief Protected helper struct for storing the Certificate chains
     * received from the Responder
     */
    struct SlotClass
    {
        std::vector<uint8_t> Digest;
        std::vector<uint8_t> Certificates; // TODO should unnecessary in the en
        std::vector<mbedtls_x509_crt*>
            MCertificates; // TODO should be abstracted in the end

        /** @brief Offset into Certificates[] where the DER data starts
         */
        size_t CertificateOffset = 0;

        /** @brief Holder for the SlotInfoEnum bits
         */
        uint8_t GotInfo = 0;
        static_assert(sizeof(GotInfo) * 8 >=
                      static_cast<std::underlying_type_t<SlotInfoEnum>>(
                          SlotInfoEnum::NUM));

        /** @brief Mark the specified SlotInfoEnum as "available", to be later
         * queried by ConnectionClass::slotHasInfo()
         */
        void markInfo(SlotInfoEnum info)
        {
            GotInfo |=
                1 << static_cast<std::underlying_type_t<SlotInfoEnum>>(info);
        }

        /** @brief Gets the first certificate from the chain, pressumed to be
         * the CA root certificate
         */
        mbedtls_x509_crt* getRootCert() const
        {
            // assert(MCertificates.size() >= 2);
            if (MCertificates.empty())
            {
                return nullptr;
            }
            return MCertificates[0];
        }
        /** @brief Gets the last certificate from the chain, pressumed to be the
         * Responder leaf certificate
         */
        mbedtls_x509_crt* getLeafCert() const
        {
            // assert(MCertificates.size() >= 2);
            if (MCertificates.empty())
            {
                return nullptr;
            }
            return MCertificates[MCertificates.size() - 1];
        }

        /** @brief clears all the fields of the given slot
         */
        void clear()
        {
            GotInfo = 0;
            CertificateOffset = 0;

            Digest.clear();
            Certificates.clear();

            for (auto cert : MCertificates)
            {
                mbedtls_x509_crt_free(cert);
                delete cert;
            }
            MCertificates.clear();
        }
    };

    /** @brief This function interprets the response previously stored in
     * ResponseBuffer
     *  @param[out] packet - The response type and variable into which the
     * response should be decoded into
     *  @param[in] fargs - Any additional information that may be needed for
     * decoding the packet, typically PacketDecodeInfo
     */
    template <typename T, typename... Targs>
    RetStat interpretResponse(T& packet, Targs... fargs);

    /** @brief Sends a request and sets up a wait for a response
     *  @param[in] request - The request to send
     *  @param[in] response - The type of response to setup the wait for, the
     * value is actually ignored, only the type is relevant
     *  @param[in] bufidx - The buffer to which the request should be appended
     * (further details in BufEnum description, if BufEnum::NUM then the request
     * will not be appended to any buffer
     *  @param[in] timeout - The response timeout
     *  @param[in] retry - The number of times the request should be
     * automatically retried if a response was not received
     */
    template <typename T, typename R>
    RetStat sendRequestSetupResponse(const T& request, const R& response,
                                     BufEnum bufidx = BufEnum::NUM,
                                     timeout_ms_t timeout = TIMEOUT_MS_INFINITE,
                                     uint16_t retry = 4);

    /** @brief This is the common implementation for all the public
     * refreshMeasurements variants
     */
    RetStat refreshMeasurementsInternal();

    /** @brief Low-level, typically shouldn't be used, sends a request
     */
    template <typename T>
    RetStat sendRequest(const T& packet, BufEnum bufidx = BufEnum::NUM);

    /** @brief Low-level, typically shouldn't be used, sets up information that
     * we're waiting for a response packet of the given type
     */
    template <typename T>
    RetStat asyncResponse();

    /** @brief Clears a previously setup response timeout
     */
    void clearTimeout();

    std::vector<uint8_t> SendBuffer;
    timeout_ms_t SendTimeout = 0;
    uint16_t SendRetry = 0;

    /** @brief Buffer for the received response from which interpretResponse
     * decodes the packet
     */
    std::vector<uint8_t> ResponseBuffer;

    /** @brief Offset into ResponseBuffer where the actual spdm packet starts,
     * before the offset is the transport layer data
     */
    size_t ResponseBufferSPDMOffset = 0;

    ContextClass* Context = nullptr;
    TransportClass* Transport = nullptr;
    mutable LogClass Log;

    /** @brief All versions reported by the Responder as being supported
     */
    std::vector<PacketVersionNumber> SupportedVersions;

    /** @brief The choosen version for communicating with the Responder
     */
    MessageVersionEnum MessageVersion = MessageVersionEnum::UNKNOWN;

    /** @brief The decodeded Algorithms response from the Responder
     */
    PacketAlgorithmsResponseVar Algorithms;

    /** @brief The per certificate slot information queried from the Responder
     */
    std::array<SlotClass, slotNum> Slots;

    TimingClass Timings;

    /** @brief Buffers for storing the communication flow and computing M1/M2
     * and L1/L2 hashes
     */
    std::array<std::vector<uint8_t>, static_cast<size_t>(BufEnum::NUM)> Bufs;

    /** @brief Low-level helper metheod
     */
    std::vector<uint8_t>& refBuf(BufEnum bufidx)
    {
        return Bufs[static_cast<std::underlying_type_t<BufEnum>>(bufidx)];
    }
    /** @brief Low-level helper metheod
     */
    const std::vector<uint8_t>& refBuf(BufEnum bufidx) const
    {
        return Bufs[static_cast<std::underlying_type_t<BufEnum>>(bufidx)];
    }

    /** @brief Calculates the given hashtype of the given storage buffer
     */
    void hashBuf(std::vector<uint8_t>& hash, HashEnum hashtype, BufEnum bufidx)
    {
        HashClass::compute(hash, hashtype, refBuf(bufidx));
    }

    /** @brief Low-level helper metheod
     */
    void appendToBuf(BufEnum bufidx, uint8_t* data, size_t size)
    {
        // HashM1M2.update(data, size);
        std::vector<uint8_t>& buf = refBuf(bufidx);
        size_t off = buf.size();
        buf.resize(off + size);
        memcpy(&buf[off], data, size);
    }
    /** @brief Low-level helper metheod
     */
    void appendRecvToBuf(BufEnum bufidx)
    {
        appendToBuf(bufidx, &ResponseBuffer[ResponseBufferSPDMOffset],
                    ResponseBuffer.size() - ResponseBufferSPDMOffset);
    }

    /** @brief This contains certain information from some requests necessary
     * for decoding the expected response packet
     */
    PacketDecodeInfo packetDecodeInfo;

    /** @brief Storage for the received and decoded measurements
     */
    DMTFMeasurementsContainer DMTFMeasurements;

    /** @brief Storage for the final L1/L2 hash
     */
    std::vector<uint8_t> MeasurementsHash;

    /** @brief Storage for the Responder signature of the L1/L2 hash
     */
    std::vector<uint8_t> MeasurementsSignature;

    /** @brief Storage for the nonce used during communication, it's  either the
     * value passed to refreshMeasurements, or a random value
     */
    nonce_array_32 MeasurementNonce{};

    /** @brief A bitmask of the requested measurements as passed to
     * refreshMeasurements
     */
    std::bitset<256> MeasurementIndices;

    /** @brief The certificate slot index that was passed to refreshMeasurements
     * and is used during communication
     */
    SlotIdx CertificateSlotIdx = slotNum;

    /** @brief The response that we're expecting to receive typically setup by
     * asyncResponse called by sendRequestSetupResponse
     */
    RequestResponseEnum WaitingForResponse = RequestResponseEnum::INVALID;

    /** @brief Bitmask for which ConnectionInfoEnum we're holding used by
     * markInfo and hasInfo
     */
    uint8_t GotInfo = 0;
    static_assert(sizeof(GotInfo) * 8 >=
                  static_cast<std::underlying_type_t<ConnectionInfoEnum>>(
                      ConnectionInfoEnum::NUM));

    /** @brief Marks the given ConnectionInfoEnum as being received/available,
     * can be queried with hasInfo
     */
    void markInfo(ConnectionInfoEnum info)
    {
        GotInfo |=
            1 << static_cast<std::underlying_type_t<ConnectionInfoEnum>>(info);
    }

    /** @brief Low-level helper function for getting the first MeasurementIndex
     * that should be requested from the Responder
     */
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

    /** @brief Helper function for choosing the SPDM version that should be used
     * for communication
     */
    RetStat chooseVersion();
};

} // namespace spdmcpp
