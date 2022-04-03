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

constexpr auto mctpDefaultPath = "/xyz/openbmc_project/mctp";

namespace spdmd
{
namespace dbus_api
{

Responder::Responder(SpdmdAppContext& appCtx, const std::string& path,
                     uint8_t eid, const std::string& inventoryPath) :
    ResponderIntf(appCtx.bus, (path + "/" + std::to_string(eid)).c_str()),
    appContext(appCtx), Connection(&appCtx.context), Transport(eid, *this)
{
    {
        std::vector<std::tuple<std::string, std::string, std::string>> prop;

        prop.emplace_back(
            "transport_object", "spdm_responder_object",
            sdbusplus::message::object_path(
                std::string(mctpDefaultPath) + "/0/" +
                std::to_string(eid))); // TODO proper value for the 0?!

        prop.emplace_back("inventory_object", "spdm_responder_object",
                          sdbusplus::message::object_path(inventoryPath));

        associations(std::move(prop));
    }
    Connection.registerTransport(&Transport);

    auto rs = Connection.initConnection();
    SPDMCPP_LOG_TRACE_RS(getLog(), rs);
}

Responder::~Responder()
{
    Connection.unregisterTransport(&Transport);
}

void Responder::syncSlotsInfo()
{
    CertificatesContainerType certs;
    MeasurementsContainerType meas;

    for (ConnectionClass::SlotIdx idx = 0; idx < ConnectionClass::slotNum;
         ++idx)
    {
        if (Connection.slothasInfo(idx, SlotInfoEnum::CERTIFICATES))
        {
            std::vector<uint8_t> cert;
            if (Connection.getCertificatesDER(cert, idx))
            {
                certs.resize(certs.size() + 1);

                std::get<0>(certs.back()) = idx;
                std::swap(cert, std::get<1>(certs.back()));
            }
        }
    }
    if (Connection.hasInfo(ConnectionInfoEnum::MEASUREMENTS))
    {
        const ConnectionClass::DMTFMeasurementsContainer& src =
            Connection.getDMTFMeasurements();
        for (auto& field : src)
        {
            meas.resize(meas.size() + 1);
            auto& m = meas.back();

            std::get<0>(m) = field.first;
            std::get<1>(m) = field.second.Min.Type;
            std::get<2>(m) = std::vector<uint8_t>(field.second.ValueVector);
        }
    }
    measurementsHash(Connection.getSignedMeasurementsHash());
    {
        const std::vector<uint8_t>& l2 =
            Connection.getSignedMeasurementsBuffer();
        const std::vector<uint8_t>& sig = Connection.getMeasurementsSignature();

        std::vector<uint8_t> buf;
        buf.reserve(l2.size() + sig.size());
        buf.insert(buf.end(), l2.begin(), l2.end());
        buf.insert(buf.end(), sig.begin(), sig.end());

        signedMeasurements(std::move(buf));
        measurementsSignature(sig);
    }

    {
        const nonce_array_32& arr = Connection.getMeasurementNonce();
        std::vector<uint8_t> nonc;
        nonc.reserve(arr.size());
        nonc.insert(nonc.end(), arr.begin(), arr.end());
        nonce(nonc);
    }
    certificate(certs);
    measurements(meas);
    updateLastUpdateTime();
}

spdmcpp::RetStat Responder::handleRecv(std::vector<uint8_t>& buf)
{
    std::swap(buf, Connection.getResponseBufferRef()); // TODO stupid workaround

    auto rs = Connection.handleRecv();

    if (isError(rs))
    {
        switch (rs)
        {
            case RetStat::ERROR_BUFFER_TOO_SMALL:
            case RetStat::ERROR_WRONG_REQUEST_RESPONSE_CODE:
            case RetStat::ERROR_UNKNOWN_REQUEST_RESPONSE_CODE:
                status(SPDMStatus::Error_RequesterCommunication);
                appContext.reportError("SPDM requester communication fail");
                break;
            case RetStat::ERROR_RESPONSE:
                status(SPDMStatus::Error_Responder);
                appContext.reportError("SPDM responder response fail");
                break;
            case RetStat::ERROR_CERTIFICATE_CHAIN_DIGEST_INVALID:
            case RetStat::ERROR_ROOT_CERTIFICATE_HASH_INVALID:
            case RetStat::ERROR_CERTIFICATE_CHAIN_VERIFIY_FAILED:
                status(SPDMStatus::Error_CertificateValidation);
                appContext.reportError("SPDM certificate validation fail");
                break;
            case RetStat::ERROR_AUTHENTICATION_FAILED:
                status(SPDMStatus::Error_AuthenticationFailed);
                appContext.reportError("SPDM authentication fail");
                break;
            case RetStat::ERROR_MEASUREMENT_SIGNATURE_VERIFIY_FAILED:
                status(
                    SPDMStatus::Error_MeasurementsSignatureVerificationFailed);
                appContext.reportError(
                    "SPDM measurements signature verification fail");
                break;
            default:
                status(SPDMStatus::Error_Other);
                appContext.reportError("SPDM other error fail");
        }
        assert(!Connection.isWaitingForResponse());
        return rs;
    }

    ConnectionClass::SlotIdx slotidx =
        Connection.getCurrentCertificateSlotIdx();

    if (!Connection.isWaitingForResponse())
    {
        syncSlotsInfo();
        updateLastUpdateTime();
        status(SPDMStatus::Success);
    }
    else if (Connection.slothasInfo(slotidx, SlotInfoEnum::CERTIFICATES))
    {
        syncSlotsInfo();
        status(SPDMStatus::GettingMeasurements);
    }
    else if (Connection.hasInfo(ConnectionInfoEnum::ALGORITHMS))
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
    else if (Connection.hasInfo(ConnectionInfoEnum::CHOOSEN_VERSION))
    {
        version(static_cast<uint8_t>(Connection.getMessageVersion()));
        status(SPDMStatus::GettingCertificates);
    }
    return rs;
}

void Responder::refresh(uint8_t slot, std::vector<uint8_t> nonc,
                        std::vector<uint8_t> measurementIndices,
                        uint32_t sessionId)
{
    if (Connection.isWaitingForResponse())
    {
        // if we're busy processing ignore the refresh call
        // TODO arguably it'd be better to either cancel the current and perform
        // the new refresh or to queue the request for processing after the
        // current one is done
        getLog().iprintln(
            "WARNING - refresh ignored because previous one is still processing!");
        return;
    }
    status(SPDMStatus::Initializing);
    updateLastUpdateTime();

    if (sessionId)
    {
        getLog().iprintln("WARNING - sessionId unsupported!");
    }

    std::bitset<256> meas;
    if (measurementIndices.empty() ||
        (measurementIndices.size() == 1 && measurementIndices[0] == 255))
    {
        meas.set(255);
    }
    else
    {
        for (auto ind : measurementIndices)
        {
            if (ind >= 1 && ind < 255)
            {
                meas.set(ind);
            }
            else
            {
                getLog().iprint("WARNING - invalid measurement index value '");
                getLog().print(ind);
                getLog().println(
                    "' when specifying multiple indices, ignoring this value!");
            }
        }
        if (meas.none())
        {
            // this would happen if all values in the array were incorrect,
            // fallback to the default of 255
            meas.set(255);
        }
    }

    if (nonc.size() == 32)
    {
        auto rs = Connection.refreshMeasurements(
            slot, *reinterpret_cast<nonce_array_32*>(nonc.data()), meas);
        SPDMCPP_LOG_TRACE_RS(getLog(), rs);
    }
    else
    {
        if (!nonc.empty())
        {
            getLog().iprint("WARNING - nonce has invalid size = ");
            getLog().println(nonc.size());
        }
        auto rs = Connection.refreshMeasurements(slot, meas);
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

spdmcpp::RetStat MctpTransportClass::setupTimeout(spdmcpp::timeout_ms_t timeout)
{
    sdeventplus::Event& event = responder.appContext.event;
    assert(!time);
    // TODO !!! verify we're not leaking anything !!!
    auto timeCb = [this](
                      sdeventplus::source::Time<clockId>& /*source*/,
                      sdeventplus::source::Time<clockId>::TimePoint /*time*/) {
        delete time; // TODO !!! is this safe? !!!
        time = nullptr;

        auto rs = responder.Connection.handleTimeout();
        if (rs == spdmcpp::RetStat::ERROR_TIMEOUT)
        {
            // no retry attempted, fail with timeout
            responder.status(Responder::SPDMStatus::Error_ConnectionTimeout);
        }
        else if (isError(rs))
        {
            responder.status(Responder::SPDMStatus::Error_Other);
        }
    };
    time = new sdeventplus::source::Time<clockId>(
        event,
        sdeventplus::Clock<clockId>(event).now() +
            std::chrono::milliseconds{timeout},
        std::chrono::milliseconds{1}, std::move(timeCb));
    return RetStat::OK;
}

bool MctpTransportClass::clearTimeout()
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
