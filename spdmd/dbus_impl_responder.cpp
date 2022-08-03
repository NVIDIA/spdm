#include "dbus_impl_responder.hpp"

#include "xyz/openbmc_project/Common/error.hpp"

#include <sdeventplus/event.hpp>
#include <sdeventplus/source/io.hpp>
#include <sdeventplus/source/time.hpp>

#include <chrono>
#include <iostream>

using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using namespace spdmcpp;

constexpr auto mctpDefaultPath = "/xyz/openbmc_project/mctp";

namespace spdmd
{
namespace dbus_api
{

Responder::Responder(SpdmdAppContext& appCtx, const std::string& path,
                     uint8_t eid,
                     const sdbusplus::message::object_path& mctpPath,
                     const sdbusplus::message::object_path& invPath) :
    ResponderIntf(appCtx.bus, path.c_str(), action::defer_emit),
    appContext(appCtx), log(std::cerr), connection(appCtx.context, log),
    transport(eid, *this), inventoryPath(invPath)
{
    {
        std::vector<std::tuple<std::string, std::string, std::string>> prop;

        prop.emplace_back("transport_object", "spdm_responder_object",
                          mctpPath);
        prop.emplace_back("inventory_object", "spdm_responder_object",
                          invPath);

        associations(std::move(prop));
    }
    connection.registerTransport(transport);

    emit_object_added();
}

Responder::~Responder()
{
    connection.unregisterTransport(transport);
}

void Responder::updateAlgorithmsInfo()
{
    switch (connection.getMeasurementHashEnum())
    {
        case HashEnum::SHA_256:
            hashingAlgorithm(HashingAlgorithms::SHA_256);
            break;
        case HashEnum::SHA_384:
            hashingAlgorithm(HashingAlgorithms::SHA_384);
            break;
        case HashEnum::SHA_512:
            hashingAlgorithm(HashingAlgorithms::SHA_512);
            break;
        case HashEnum::NONE:
        case HashEnum::INVALID:
        default:
            hashingAlgorithm(HashingAlgorithms::None);
            break;
    }
    switch (connection.getSignatureEnum())
    {
// NOLINTNEXTLINE cppcoreguidelines-macro-usage,-warnings-as-errors
#define DTYPE(name)                                                            \
        case SignatureEnum::name:                                                  \
            signingAlgorithm(SigningAlgorithms::name);                             \
            break;
                DTYPE(RSASSA_2048)
                DTYPE(RSAPSS_2048)
                DTYPE(RSASSA_3072)
                DTYPE(RSAPSS_3072)
                DTYPE(RSASSA_4096)
                DTYPE(RSAPSS_4096)
                DTYPE(ECDSA_ECC_NIST_P256)
                DTYPE(ECDSA_ECC_NIST_P384)
                DTYPE(ECDSA_ECC_NIST_P521)
#undef DTYPE
        case SignatureEnum::NONE:
        case SignatureEnum::INVALID:
        default:
            signingAlgorithm(SigningAlgorithms::None);
            break;
    }
}

void Responder::updateCertificatesInfo()
{
    CertificatesContainerType certs;
    for (ConnectionClass::SlotIdx idx = 0; idx < ConnectionClass::slotNum;
         ++idx)
    {
        if (connection.slotHasInfo(idx, SlotInfoEnum::CERTIFICATES))
        {
            std::string cert;
            if (connection.getCertificatesPEM(cert, idx))
            {
                certs.emplace_back(idx, std::move(cert));
            }
        }
    }
    certificate(std::move(certs));
}

void Responder::syncSlotsInfo()
{
    MeasurementsContainerType meas;

    updateAlgorithmsInfo();
    updateCertificatesInfo();

    if (connection.hasInfo(ConnectionInfoEnum::MEASUREMENTS))
    {
        const ConnectionClass::DMTFMeasurementsContainer& src =
            connection.getDMTFMeasurements();

        std::transform(src.begin(), src.end(), std::back_inserter(meas),
                       [](const auto& field) {
                           return MeasurementsContainerType::value_type(
                               field.first, field.second.Min.Type,
                               field.second.ValueVector);
                       });
    }
    measurementsHash(connection.getSignedMeasurementsHash());
    {
        const std::vector<uint8_t>& l2 =
            connection.getSignedMeasurementsBuffer();
        const std::vector<uint8_t>& sig = connection.getMeasurementsSignature();

        std::vector<uint8_t> buf;
        buf.reserve(l2.size() + sig.size());
        buf.insert(buf.end(), l2.begin(), l2.end());
        buf.insert(buf.end(), sig.begin(), sig.end());

        signedMeasurements(std::move(buf));
        measurementsSignature(sig);
    }

    {
        const nonce_array_32& arr = connection.getMeasurementNonce();
        std::vector<uint8_t> nonc;
        nonc.reserve(arr.size());
        nonc.insert(nonc.end(), arr.begin(), arr.end());
        nonce(std::move(nonc));
    }
    measurements(std::move(meas));
    updateLastUpdateTime();
}

void Responder::handleError(spdmcpp::RetStat rs)
{
    updateLastUpdateTime();
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
            status(SPDMStatus::Error_MeasurementsSignatureVerificationFailed);
            appContext.reportError(
                "SPDM measurements signature verification fail");
            break;
        case RetStat::ERROR_TIMEOUT:
            status(Responder::SPDMStatus::Error_ConnectionTimeout);
            appContext.reportError("SPDM timeout");
            break;
        default:
            status(SPDMStatus::Error_Other);
            appContext.reportError(std::string("SPDM other error: ") +
                                   get_cstr(rs));
    }
    SPDMCPP_ASSERT(!connection.isWaitingForResponse());
}

spdmcpp::RetStat Responder::handleEventForRefresh(spdmcpp::EventClass& ev)
{
    auto rs = connection.handleEvent(ev);

    if (isError(rs))
    {
        handleError(rs);
        return rs;
    }

    if (!ev.is<EventReceiveClass>())
    {
        return rs;
    }

    ConnectionClass::SlotIdx slotidx = connection.getCurrentCertificateSlotIdx();

    if (!connection.isWaitingForResponse())
    {
        syncSlotsInfo();
        updateLastUpdateTime();
        status(SPDMStatus::Success);
    }
    else if (connection.slotHasInfo(slotidx, SlotInfoEnum::CERTIFICATES))
    {
        updateCertificatesInfo();
        status(SPDMStatus::GettingMeasurements);
    }
    else if (connection.hasInfo(ConnectionInfoEnum::ALGORITHMS))
    {
        updateAlgorithmsInfo();
        status(SPDMStatus::GettingCertificates);
    }
    else if (connection.hasInfo(ConnectionInfoEnum::CHOOSEN_VERSION))
    {
        version(static_cast<uint8_t>(connection.getMessageVersion()));
        status(SPDMStatus::GettingCertificates);
    }
    return rs;
}

void Responder::refresh(uint8_t slotIndex, std::vector<uint8_t> nonc,
                        std::vector<uint8_t> measurementIndices,
                        uint32_t sessionId)
{
    if (connection.isWaitingForResponse())
    {
        // if we're busy processing ignore the refresh call
        // TODO arguably it'd be better to either cancel the current and perform
        // the new refresh or to queue the request for processing after the
        // current one is done
        getLog().iprintln(
            "WARNING - refresh ignored because previous one is still processing!");
        return;
    }

    if (slotIndex >= ConnectionClass::slotNum)
    {
        getLog().iprintln(
            "WARNING - refresh ignored because slotIndex is invalid!");
        status(SPDMStatus::Error_InvalidArguments);
        return;
    }
    if (!nonc.empty() && nonc.size() != 32)
    {
        getLog().iprint(
            "WARNING - refresh ignored because nonc has invalid size = ");
        getLog().println(nonc.size());
        status(SPDMStatus::Error_InvalidArguments);
        return;
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
                status(SPDMStatus::Error_InvalidArguments);
                return;
            }
        }
    }

    eventHandler = &spdmd::dbus_api::Responder::handleEventForRefresh;

    status(SPDMStatus::Initializing);

    slot(slotIndex);

    updateLastUpdateTime();

    if (sessionId)
    {
        getLog().iprintln("WARNING - sessionId unsupported!");
    }

    if (nonc.size() == 32)
    {
        auto rs = connection.refreshMeasurements(
            slotIndex,
            // NOLINTNEXTLINE cppcoreguidelines-pro-type-reinterpret-cast
            *reinterpret_cast<nonce_array_32*>(nonc.data()), meas);
        SPDMCPP_LOG_TRACE_RS(getLog(), rs);
    }
    else
    {
        auto rs = connection.refreshMeasurements(slotIndex, meas);
        SPDMCPP_LOG_TRACE_RS(getLog(), rs);
    }
}

#if FETCH_SERIALNUMBER_FROM_RESPONDER != 0

void Responder::refreshSerialNumber()
{
    if (connection.isWaitingForResponse())
    {
        // if we're busy processing ignore the refresh call
        getLog().iprintln(
            "WARNING - refreshSerialNumber() ignored because a previous refresh is still processing!");
        return;
    }
    eventHandler = &spdmd::dbus_api::Responder::handleEventForSerialNumber;

    std::bitset<256> meas;
    meas.set(FETCH_SERIALNUMBER_FROM_RESPONDER);

    auto rs = connection.refreshMeasurements(0, meas);
    SPDMCPP_LOG_TRACE_RS(getLog(), rs);
}

spdmcpp::RetStat
    Responder::handleEventForSerialNumber(spdmcpp::EventClass& event)
{
    auto rs = connection.handleEvent(event);

    if (isError(rs) || connection.isWaitingForResponse())
    {
        if (connection.slotHasInfo(connection.getCurrentCertificateSlotIdx(),
                                SlotInfoEnum::CERTIFICATES))
        {
            updateCertificatesInfo();
            updateLastUpdateTime();
        }
        return rs;
    }
    
    if (connection.hasInfo(ConnectionInfoEnum::MEASUREMENTS))
    {
        const ConnectionClass::DMTFMeasurementsContainer& src =
            connection.getDMTFMeasurements();
        auto iter = src.find(FETCH_SERIALNUMBER_FROM_RESPONDER);
        if (iter != src.end() && iter->second.Min.Type == 0x82)
        {
            // if available and has the correct type:
            // 0x80 "Raw bit stream"
            // 0x02 "Hardware configuration, such as straps, debug modes."
            auto method = inventoryService.new_method_call(
                appContext.bus, std::string(inventoryPath).c_str(),
                "org.freedesktop.DBus.Properties", "Set");

            method.append(
                "xyz.openbmc_project.Inventory.Decorator.Asset", "SerialNumber",
                std::variant<std::string>(toEscapedString(iter->second.ValueVector)));

            appContext.bus.call_noreply(method);
        }
    }
    return rs;
}
#endif

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
    sdeventplus::Event& event = responder.getEvent();

    time = make_unique<SpdmdAppContext::Timer>(
        event,
        SpdmdAppContext::Clock(event).now() +
            std::chrono::milliseconds{timeout},
        std::chrono::milliseconds{1},
        [this](SpdmdAppContext::Timer& /*source*/,
               SpdmdAppContext::Timer::TimePoint /*time*/) {
            timeoutCallback();
        });

    return RetStat::OK;
}

void MctpTransportClass::timeoutCallback()
{
    time.reset(nullptr);
    spdmcpp::EventTimeoutClass ev;
    responder.handleEvent(ev);
}

bool MctpTransportClass::clearTimeout()
{
    if (time)
    {
        time.reset(nullptr);
        return true;
    }
    return false;
}

} // namespace dbus_api
} // namespace spdmd
