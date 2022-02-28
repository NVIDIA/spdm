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

constexpr auto MCTP_DEFAULT_PATH = "/xyz/openbmc_project/mctp";

namespace spdmd
{
namespace dbus_api
{

Responder::Responder(SpdmdAppContext& appCtx, const std::string& path,
                     uint8_t eid) :
    ResponderIntf(appCtx.bus, (path + "/" + std::to_string(eid)).c_str()),
    appContext(appCtx), 
    Connection(&appCtx.context), 
    Transport(eid, *this)
{
    {
        std::vector<std::tuple<std::string, std::string, std::string>> prop;
        prop.emplace_back(
            "transport_object", "spdm_responder_object",
            sdbusplus::message::object_path(
                std::string(MCTP_DEFAULT_PATH) + "/0/" +
                std::to_string(eid))); // TODO proper value for the 0?!
        associations(std::move(prop));
    }
    Connection.register_transport(&Transport);

    Connection.reset_connection();
    auto rs = Connection.init_connection();
    SPDMCPP_LOG_TRACE_RS(getLog(), rs);
}

Responder::~Responder()
{
    Connection.unregister_transport(&Transport);
}

void Responder::syncSlotsInfo()
{
    CertificatesContainerType certs;
    MeasurementsContainerType meas;

    for (ConnectionClass::SlotIdx idx = 0; idx < ConnectionClass::SLOT_NUM;
         ++idx)
    {
        {
            std::vector<uint8_t> cert;
            if (Connection.getCertificatesDER(cert, idx))
            {
                certs.resize(certs.size() + 1);

                std::get<0>(certs.back()) = idx;
                std::swap(cert, std::get<1>(certs.back()));
            }
        }
        const ConnectionClass::DMTFMeasurementsContainer& src =
            Connection.getDMTFMeasurements(idx);
        if (!src.empty())
        {
            meas.resize(meas.size() + 1);
            auto& slot = meas.back();
            std::get<0>(slot) = idx;
            for (auto& field : src)
            {
                auto& dst_vec = std::get<1>(slot);
                // auto& dst_vec = dst;
                dst_vec.resize(dst_vec.size() + 1);
                auto& d = dst_vec.back();

                std::get<0>(d) = field.first;
                std::get<1>(d) = field.second.Min.Type;
                std::get<2>(d) = std::vector<uint8_t>(field.second.ValueVector);
            }
        }
    }
    /*{TODO no longer needed?! we could remove the buffer for it then and go back to a running hash...
        auto& buf = Connection.getSignedMeasurementsBuffer();
        signedMeasurements(buf);
    }*/
    {
        const nonce_array_32& arr = Connection.getMeasurementNonce();
        std::vector<uint8_t> nonc(sizeof(arr));
        memcpy(nonc.data(), arr, nonc.size());
        nonce(nonc);
    }
    certificate(certs);
    measurements(meas);
    updateLastUpdateTime();
}

spdmcpp::RetStat Responder::handleRecv(std::vector<uint8_t>& buf)
{
    std::swap(buf, Connection.getResponseBufferRef()); // TODO stupid workaround

    auto rs = Connection.handle_recv();

    if (is_error(rs))
    {
        switch (rs)
        {
            case RetStat::ERROR_BUFFER_TOO_SMALL:
            case RetStat::ERROR_WRONG_REQUEST_RESPONSE_CODE:
            case RetStat::ERROR_UNKNOWN_REQUEST_RESPONSE_CODE:
                status(SPDMStatus::Error_RequesterCommunication);
                break;
            case RetStat::ERROR_RESPONSE:
                status(SPDMStatus::Error_Responder);
                break;
            case RetStat::ERROR_CERTIFICATE_CHAIN_DIGEST_INVALID:
            case RetStat::ERROR_ROOT_CERTIFICATE_HASH_INVALID:
            case RetStat::ERROR_CERTIFICATE_CHAIN_VERIFIY_FAILED:
                status(SPDMStatus::Error_CertificateValidation);
                break;
            case RetStat::ERROR_AUTHENTICATION_FAILED:
                status(SPDMStatus::Error_AuthenticationFailed);
                break;
            case RetStat::ERROR_MEASUREMENT_SIGNATURE_VERIFIY_FAILED:
                status(
                    SPDMStatus::Error_MeasurementsSignatureVerificationFailed);
                break;
            default:
                status(SPDMStatus::Error_Other);
        }
        return rs;
    }

    if (!Connection.is_waiting_for_response())
    {
        syncSlotsInfo();
#if 0
        // TODO verify!!! and set measurements
        assert(Connection.HasInfo(ConnectionInfoEnum::MEASUREMENTS));
        const ConnectionClass::DMTFMeasurementsContainer& src =
            Connection.getDMTFMeasurements(0);

        MeasurementsContainerType dst = measurements();

        // uint8_t slotidx = 0;
        dst.resize(1);
        auto& slot = dst[0];

        std::get<0>(slot) = 0;
        for (auto& field : src)
        {
            auto& dst_vec = std::get<1>(slot);
            // auto& dst_vec = dst;
            dst_vec.resize(dst_vec.size() + 1);
            auto& d = dst_vec.back();

            std::get<0>(d) = field.first;
            std::get<1>(d) = field.second.Min.Type;
            std::get<2>(d) = std::vector<uint8_t>(field.second.ValueVector);
        }
        measurements(dst);
#endif
        updateLastUpdateTime();
        status(SPDMStatus::Success);
    }
    else if (Connection.HasInfo(ConnectionInfoEnum::CERTIFICATES))
    {
#if 0
        // TODO verify certificate!?
        uint8_t slotidx = 0;
        CertificatesContainerType certs = certificate();
        certs.resize(1);
        if (Connection.getCertificateDER(std::get<1>(certs[0]), slotidx))
        {
            certificate(certs);
            status(SPDMStatus::GettingMeasurements);
        }
#endif
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

void Responder::refresh(uint8_t slot, std::vector<uint8_t> nonc,
                        uint32_t sessionId)
{
    status(SPDMStatus::Initializing);
    updateLastUpdateTime();

    if (sessionId)
    {
        getLog().iprintln("WARNING - sessionId unsupported!");
    }

    if (nonc.size() == 32)
    {
        auto rs = Connection.refresh_measurements(
            slot, *reinterpret_cast<nonce_array_32*>(nonc.data()));
        SPDMCPP_LOG_TRACE_RS(getLog(), rs);
    }
    else
    {
        if (!nonc.empty())
        {
            getLog().iprint("WARNING - nonce has invalid size = ");
            getLog().println(nonc.size());
        }
        auto rs = Connection.refresh_measurements(slot);
        SPDMCPP_LOG_TRACE_RS(getLog(), rs);
    }
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
    sdeventplus::Event& event = responder.appContext.event;
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
