
#pragma once

#include "common.hpp"
#include "hash.hpp"

#include <mbedtls/md.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>
#include <vector>

namespace spdmcpp
{
// TODO implement warnings and global (maybe granular?) warning policies!?
//  and/or error policies as well, although those would have to be much more
//  specific I imagine...

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
};

class ConnectionClass
{
  public:
    ConnectionClass(ContextClass* context) : Context(context), Log(std::cout)
    {}
    ~ConnectionClass()
    {}

    RetStat init_connection();

    typedef uint8_t SlotIdx;
    enum : SlotIdx
    {
        SLOT_NUM = 8
    };

    RetStat try_get_version();
    RetStat try_get_capabilities();
    RetStat try_negotiate_algorithms();
    RetStat try_get_digest();
    RetStat try_get_certificate(SlotIdx idx);
    RetStat try_get_certificate_chunk(SlotIdx idx);
    RetStat try_get_measurements();

    RetStat try_challenge();

    template <class T>
    RetStat handle_recv();

    EventRetStat handle_recv();
    EventRetStat handle_timeout();

    MessageVersionEnum getMessageVersion() const
    {
        return MessageVersion;
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
        A,
        B,
        C,
        NUM,
    };

    struct SlotClass
    {
        std::vector<uint8_t> Digest;
        std::vector<uint8_t> Certificates;
        std::vector<mbedtls_x509_crt*> MCertificates;
        bool Valid = false;

        mbedtls_x509_crt* GetRootCert() const
        {
            assert(MCertificates.size() >= 2);
            return MCertificates[0];
        }
        mbedtls_x509_crt* GetLeafCert() const
        {
            assert(MCertificates.size() >= 2);
            return MCertificates[MCertificates.size() - 1];
        }
    };

    template <typename T>
    RetStat send_request(const T& packet, BufEnum bufidx = BufEnum::NUM);
    template <typename T>
    RetStat receive_response(T& packet);
    // 		template<typename T> RetStat interpret_response(T& packet);
    template <typename T, typename... Targs>
    RetStat interpret_response(T& packet, Targs... fargs);

    template <typename T>
    RetStat async_response();
    template <typename T, typename R>
    RetStat send_request_setup_response(const T& request, const R& response,
                                        BufEnum bufidx = BufEnum::NUM);

    std::vector<uint8_t> ResponseBuffer;
    size_t ResponseBufferSPDMOffset;

    ContextClass* Context = nullptr;
    LogClass Log;

    std::vector<packet_version_number> SupportedVersions;
    MessageVersionEnum MessageVersion = MessageVersionEnum::UNKNOWN;

    packet_algorithms_response_var Algorithms;
    SlotClass Slots[SLOT_NUM];

    // TODO the requirement of hashing messages before the hash function is
    // decided by the responder is quite troublesome, probably easiest to
    // calculate all supported hashes in parallel?
    // TODO test perf/memory and decide if we'll use Buffers or running hashes,
    // or a mixture
    HashClass HashM1M2;
    HashClass HashL1L2;
    std::vector<uint8_t> Bufs[static_cast<size_t>(BufEnum::NUM)];
    std::vector<uint8_t>& RefBuf(BufEnum bufidx)
    {
        return Bufs[static_cast<std::underlying_type_t<BufEnum>>(bufidx)];
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
    bool HasInfo(ConnectionInfoEnum info)
    {
        return !!(GotInfo &
                  (1 << static_cast<std::underlying_type_t<ConnectionInfoEnum>>(
                       info)));
    }

    RetStat choose_version();
};

} // namespace spdmcpp
