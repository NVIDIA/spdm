#include "dbus_impl_responder.hpp"

#include "xyz/openbmc_project/Common/error.hpp"

#include <sdeventplus/event.hpp>
#include <sdeventplus/source/io.hpp>
#include <sdeventplus/source/time.hpp>

#include <chrono>
#include <iostream>

// #include <cassert>

using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using namespace spdmcpp;

namespace spdmd
{
namespace dbus_api
{

Responder::Responder(ResponderContext& ctx, const std::string& path,
                     uint8_t eid) :
    ResponderIntf(ctx.bus, (path + "/" + std::to_string(eid)).c_str()),
    context(ctx), Connection(&ctx.context), Transport(eid, *this)
{
    ResponderIntf::eid(eid);

    Connection.register_transport(&Transport);
}

Responder::~Responder()
{
    Connection.unregister_transport(&Transport);
}

spdmcpp::RetStat Responder::handleRecv(std::vector<uint8_t>& buf)
{
    std::swap(buf, Connection.getResponseBufferRef()); // TODO stupid workaround

    auto rs = Connection.handle_recv();

    if (is_error(rs))
    {
        // TODO !!!
        //	status(SPDMStatus::Error_ConnectionTimeout);
        status(SPDMStatus::Error_Other);
        return rs;
    }

    if (!Connection.is_waiting_for_response())
    {
        // TODO verify!!! and set measurements
        assert(Connection.HasInfo(ConnectionInfoEnum::MEASUREMENTS));
        const ConnectionClass::DMTFMeasurementsContainer& src =
            Connection.getDMTFMeasurements();

        MeasurementsContainerType dst;

        //	std::get<0>(dst) = src.size();
        for (auto& field : src)
        {
            // 			auto& dst_vec = std::get<1>(dst);
            auto& dst_vec = dst;
            dst_vec.resize(dst_vec.size() + 1);
            auto& d = dst_vec.back();

            //	std::get<0>(d) = std::string(reinterpret_cast<const
            // char*>(field.second.ValueVector.data()),
            // field.second.ValueVector.size());
            std::get<0>(d) = std::vector<uint8_t>(field.second.ValueVector);

            // TODO either encode to string or change to some raw/binary type if
            // possible?
            if (field.second.Min.Type & 0x80)
            {
                std::get<2>(d) = HashingAlgorithms::None;
            }
            else
            {
                std::get<2>(d) = hashingAlgorithm();
            }
            //	field.second.print_ml(Connection.getLog());
        }
        measurements(dst);
        updateLastUpdateTime();
        status(SPDMStatus::Success);
    }
    else if (Connection.HasInfo(ConnectionInfoEnum::CERTIFICATES))
    {
        // TODO verify certificate!?
        std::string str;
        if (Connection.getCertificates(str))
        {
            certificate(str);
            status(SPDMStatus::GettingMeasurements);
        }
    }
    else if (Connection.HasInfo(ConnectionInfoEnum::ALGORITHMS))
    {
        switch (Connection.getMeasurementHash())
        {
            case HashEnum::NONE:
                hashingAlgorithm(HashingAlgorithms::None);
                break;
            case HashEnum::INVALID:
                hashingAlgorithm(HashingAlgorithms::None);
                break;
            case HashEnum::SHA_256:
                hashingAlgorithm(HashingAlgorithms::SHA_256);
                break;
            case HashEnum::SHA_384:
                hashingAlgorithm(HashingAlgorithms::SHA_384);
                break;
            case HashEnum::SHA_512:
                hashingAlgorithm(HashingAlgorithms::SHA_512);
                break;
                //	case HashEnum::SHA3_:
                // hashingAlgorithm(HashingAlgorithms::SHA_);		break;
            default:
                hashingAlgorithm(HashingAlgorithms::OEM);
                break;
        }
        status(SPDMStatus::GettingCertificates);
    }
    else if (Connection.HasInfo(ConnectionInfoEnum::CHOOSEN_VERSION))
    {
        version(static_cast<uint8_t>(Connection.getMessageVersion()));
        status(SPDMStatus::GettingCertificates);
    }
    return rs;
}

void Responder::refresh()
{
    status(SPDMStatus::Initializing);
    version(0);
    hashingAlgorithm(HashingAlgorithms::None);
    certificate("");
    measurements(MeasurementsContainerType());
    updateLastUpdateTime();

    Connection.reset_connection();
    auto rs = Connection.init_connection();
    SPDMCPP_LOG_TRACE_RS(getLog(), rs);
}

void Responder::updateLastUpdateTime()
{
    auto now =
        std::chrono::system_clock::now(); // TODO why is utc_clock undeclared!?

    lastUpdate(
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch())
            .count());
}

spdmcpp::RetStat
    MCTP_TransportClass::setup_timeout(spdmcpp::timeout_ms_t timeout)
{
    sdeventplus::Event& event = responder.context.event;
    assert(!time);
    // TODO !!! verify we're not leaking anything !!!
    auto time_cb = [this](
                       sdeventplus::source::Time<clockId>& /*source*/,
                       sdeventplus::source::Time<clockId>::TimePoint /*time*/) {
        delete time; // TODO !!! is this safe? !!!
        time = nullptr;

        auto rs = responder.Connection.handle_timeout();
        if (rs == spdmcpp::RetStat::ERROR_TIMEOUT)
        {
            // no retry attempted, fail with timeout
            responder.status(Responder::SPDMStatus::Error_ConnectionTimeout);
        }
        else if (is_error(rs))
        {
            responder.status(Responder::SPDMStatus::Error_Other);
        }
    };
    time = new sdeventplus::source::Time<clockId>(
        event,
        sdeventplus::Clock<clockId>(event).now() +
            std::chrono::milliseconds{timeout},
        std::chrono::milliseconds{1}, std::move(time_cb));
    return RetStat::OK;
}

bool MCTP_TransportClass::clear_timeout()
{
    if (time)
    {
        delete time;
        time = nullptr;
        return true;
    }
    return false;
}

} // namespace dbus_api
} // namespace spdmd
