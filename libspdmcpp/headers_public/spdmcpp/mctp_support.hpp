
#pragma once

#include "common.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

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
// these are for use with the mctp-demux-daemon

class MCTP_TransportClass : public TransportClass
{
  public:
    MCTP_TransportClass(uint8_t eid) : EID(eid)
    {}
    virtual ~MCTP_TransportClass()
    {}

    void SetEID(uint8_t eid)
    {
        assert(EID == 0);
        EID = eid;
    }

    virtual RetStat encode_pre(std::vector<uint8_t>& /*buf*/,
                               LayerState& lay) override
    {
        set_layer_size(lay, sizeof(header_type));
        return RetStat::OK;
    }
    virtual RetStat encode_post(std::vector<uint8_t>& buf,
                                LayerState& lay) override
    {
        auto& header = get_header_ref<header_type>(buf, lay);
        header.eid = EID;
        header.type = MCTPMessageTypeEnum::SPDM;
        return RetStat::OK;
    }

    virtual RetStat decode(std::vector<uint8_t>& buf, LayerState& lay) override
    {
        set_layer_size(lay, sizeof(header_type));
        auto& header = get_header_ref<header_type>(buf, lay);
        if (header.type != MCTPMessageTypeEnum::SPDM)
        {
            return RetStat::ERROR_UNKNOWN;
        }
        return RetStat::OK;
    }

    static RetStat peek_eid(std::vector<uint8_t>& buf, LayerState& lay,
                            uint8_t& eid)
    {
        set_layer_size(lay, sizeof(header_type));
        auto& header = get_header_ref<header_type>(buf, lay);
        if (header.type != MCTPMessageTypeEnum::SPDM)
        {
            return RetStat::ERROR_UNKNOWN;
        }
        eid = header.eid;
        return RetStat::OK;
    }

  protected:
    struct header_type
    {
        uint8_t eid;
        MCTPMessageTypeEnum type;

        static constexpr bool size_is_constant = true;
    };

    uint8_t EID = 0;
};

class MCTP_IOClass : public IOClass
{
  public:
    MCTP_IOClass(LogClass& log) : Log(log)
    {}
    ~MCTP_IOClass() override
    {}

    bool createSocket()
    {
        SPDMCPP_LOG_TRACE_FUNC(Log);
        Socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
        if (Socket == -1)
        {
            return false;
        }

        const char path[] = "\0mctp-mux";
        struct sockaddr_un addr;
        addr.sun_family = AF_UNIX;
        memcpy(addr.sun_path, path, sizeof(path) - 1);

        if (::connect(Socket, (struct sockaddr*)&addr,
                      sizeof(path) + sizeof(addr.sun_family) - 1) == -1)
        {
            Log.iprint("connect() error to mctp-demux-daemon, errno = ");
            Log.print(errno);
            Log.print(" ");
            Log.println(std::strerror(errno));
            deleteSocket();
            return false;
        }
        {
            auto type = MCTPMessageTypeEnum::SPDM;
            ssize_t ret = ::write(Socket, &type, sizeof(type));
            if (ret == -1)
            {
                Log.iprint("Failed to write spdm code to socket, errno = ");
                Log.print(errno);
                Log.print(" ");
                Log.println(strerror(errno));
                deleteSocket();
                return false;
            }
        }
        Log.iprintln("Connection success!\n");
        return true;
    }
    void deleteSocket()
    {
        close(Socket);
        Socket = -1;
    }

    RetStat write(const std::vector<uint8_t>& buf,
                  timeout_us_t timeout = TIMEOUT_US_INFINITE) override;
    RetStat read(std::vector<uint8_t>& buf,
                 timeout_us_t timeout = TIMEOUT_US_INFINITE) override;
    // 		RetStat setup_timeout(timeout_ms_t timeout) override;
    //	private://TODO !!!
    LogClass& Log;
    int Socket = -1;
};

inline RetStat MCTP_IOClass::write(const std::vector<uint8_t>& buf,
                                   timeout_us_t /*timeout*/)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    size_t sent = 0;
    while (sent < buf.size())
    {
        ssize_t ret =
            send(Socket, (void*)(buf.data() + sent), buf.size() - sent, 0);
        if (ret == -1)
        {
            printf("Send error - 0x%x\n", errno); // TODO CLEANUP
            return RetStat::ERROR_UNKNOWN;
        }
        sent += ret;
    }
    return RetStat::OK;
}

inline RetStat MCTP_IOClass::read(std::vector<uint8_t>& buf,
                                  timeout_us_t /*timeout*/)
{
    SPDMCPP_LOG_TRACE_FUNC(Log);
    buf.resize(4096); // MCTP_MAX_MSG
    ssize_t result = recv(Socket, (void*)buf.data(), buf.size(), 0);
    if (result == -1)
    {
        buf.clear();
        printf("Receive error - 0x%x\n", errno); // TODO CLEANUP
        return RetStat::ERROR_UNKNOWN;
    }
    if (result == 0)
    {
        buf.clear();
        return RetStat::ERROR_UNKNOWN;
    }
    buf.resize(result);
    return RetStat::OK;
}
#if 0
	inline RetStat MCTP_IOClass::setup_timeout(timeout_ms_t /*timeout*/)
	{
		SPDMCPP_LOG_TRACE_FUNC(Log);
	/*	constexpr sdeventplus::ClockId cid = sdeventplus::ClockId::Monotonic;
		Emulator.Timeout->set_time(sdeventplus::Clock<cid>(Emulator.Event).now() + std::chrono::microseconds{timeout});
		Emulator.Timeout->set_enabled(sdeventplus::source::Enabled::OneShot);*/
		return RetStat::OK;
	}
#endif
} // namespace spdmcpp
