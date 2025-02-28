/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dbus_impl_responder.hpp"

#include "xyz/openbmc_project/Common/error.hpp"

#include <chrono>
#include <iostream>

using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using namespace spdmcpp;

namespace spdmd
{
namespace dbus_api
{

/**
 * @brief Convert SPDM version to string
 *
 * @param version SPDM version
 * @return std::string SPDM version string
 */
inline std::string getVersionStr(const uint8_t version)
{
    switch (version)
    {
        case 0x11:
            return "1.1.0";
        case 0x10:
            return "1.0.0";
        case 0x12:
            return "1.1.2";
        default:
            return "unknown";
    }
}

Responder::Responder(SpdmdAppContext& appCtx, const std::string& path,
                     uint8_t eid,
                     const sdbusplus::message::object_path& mctpPath,
                     const sdbusplus::message::object_path& invPath,
                     std::string transportMedium, std::string bindingType,
                     std::string socketPath) :
    ResponderIntf(appCtx.getConn(), path.c_str(), action::defer_emit),
    appContext(appCtx), log(appCtx.getLog()),
    connection(appCtx.context, log, eid, std::move(socketPath)),
    transport(eid, *this, std::move(transportMedium), log),
    inventoryPath(invPath), bindingType(bindingType), eid(eid)
{
    {
        std::vector<std::tuple<std::string, std::string, std::string>> prop;

        prop.emplace_back("transport_object", "spdm_responder_object",
                          mctpPath);
        prop.emplace_back("inventory_object", "spdm_responder_object", invPath);

        associations(std::move(prop));
    }
    connection.registerTransport(transport);

    type(sdbusplus::xyz::openbmc_project::Attestation::server::
             ComponentIntegrity::SecurityTechnologyType::SPDM);
    // Initialize with empty version, will be updated when connection is
    // established
    typeVersion("");
    if (inventoryPath.filename().find("ERoT") != std::string::npos)
    {
        trustedComponentType(
            sdbusplus::xyz::openbmc_project::Inventory::Item::server::
                TrustedComponent::ComponentAttachType::Discrete);
    }
    else
    {
        trustedComponentType(
            sdbusplus::xyz::openbmc_project::Inventory::Item::server::
                TrustedComponent::ComponentAttachType::Integrated);
    }

    // Update hidden property
    static constexpr auto confName = "visible";
    sdbusplus::xyz::openbmc_project::Object::server::Enable::enabled(
        appCtx.getPropertyByEid<bool>(eid, confName).value_or(true));
    sdbusplus::xyz::openbmc_project::Attestation::server::ComponentIntegrity::
        enabled(true);

    emit_object_added();
}

Responder::~Responder()
{
    connection.unregisterTransport(transport);
}

void Responder::updateVersionInfo()
{
    version(static_cast<uint8_t>(connection.getMessageVersion()));
    typeVersion(
        getVersionStr(static_cast<uint8_t>(connection.getMessageVersion())));
}

void Responder::updateCapabilities()
{
    capabilities(
        static_cast<std::underlying_type_t<ResponderCapabilitiesFlags>>(
            connection.getCapabilitiesFlags()));
}

void Responder::updateAlgorithmsInfo()
{
    switch (connection.getMeasurementHashEnum())
    {
        case HashEnum::TPM_ALG_SHA_256:
            hashingAlgorithm(HashingAlgorithms::TPM_ALG_SHA_256);
            break;
        case HashEnum::TPM_ALG_SHA_384:
            hashingAlgorithm(HashingAlgorithms::TPM_ALG_SHA_384);
            break;
        case HashEnum::TPM_ALG_SHA_512:
            hashingAlgorithm(HashingAlgorithms::TPM_ALG_SHA_512);
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
        DTYPE(TPM_ALG_RSASSA_2048)
        DTYPE(TPM_ALG_RSAPSS_2048)
        DTYPE(TPM_ALG_RSASSA_3072)
        DTYPE(TPM_ALG_RSAPSS_3072)
        DTYPE(TPM_ALG_RSASSA_4096)
        DTYPE(TPM_ALG_RSAPSS_4096)
        DTYPE(TPM_ALG_ECDSA_ECC_NIST_P256)
        DTYPE(TPM_ALG_ECDSA_ECC_NIST_P384)
        DTYPE(TPM_ALG_ECDSA_ECC_NIST_P521)
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
    std::string certToUse;

    for (ConnectionClass::SlotIdx idx = 0; idx < ConnectionClass::slotNum;
         ++idx)
    {
        if (connection.slotHasInfo(idx, SlotInfoEnum::CERTIFICATES))
        {
            std::string cert;
            if (connection.getCertificatesPEM(cert, idx))
            {
                certToUse = cert;
                certs.emplace_back(idx, std::move(cert));
            }
        }
    }

    if (certToUse.empty())
    {
        log.iprint("No valid certificates found for EID ");
        log.println(eid);
    }

    certificate(std::move(certs));
    parseAndFillCertificate(certToUse);
}

void Responder::updateResponderVerificationStatus()
{
    responderVerificationStatus(
        sdbusplus::xyz::openbmc_project::Attestation::server::
            IdentityAuthentication::VerificationStatus::Unknown);
    for (ConnectionClass::SlotIdx idx = 0; idx < ConnectionClass::slotNum;
         ++idx)
    {
        if (connection.slotHasInfo(idx, SlotInfoEnum::CERTIFICATES))
        {
            responderVerificationStatus(
                sdbusplus::xyz::openbmc_project::Attestation::server::
                    IdentityAuthentication::VerificationStatus::Success);
            return;
        }
    }
    responderVerificationStatus(
        sdbusplus::xyz::openbmc_project::Attestation::server::
            IdentityAuthentication::VerificationStatus::Failed);
    getLog().iprint("Responder verification status failed for EID: ");
    getLog().iprintln(eid);
}

void Responder::syncSlotsInfo()
{
    MeasurementsContainerType meas;

    updateVersionInfo();
    updateAlgorithmsInfo();
    updateCertificatesInfo();
    updateResponderVerificationStatus();
    updateCapabilities();

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
    const std::string dbgIdName = "eid: " + std::to_string(connection.m_eid) +
                                  " name: " + inventoryPath.filename();
    switch (rs)
    {
        case RetStat::ERROR_BUFFER_TOO_SMALL:
        case RetStat::ERROR_WRONG_REQUEST_RESPONSE_CODE:
        case RetStat::ERROR_UNKNOWN_REQUEST_RESPONSE_CODE:
            status(SPDMStatus::Error_RequesterCommunication);
            appContext.reportError("SPDM requester communication fail on " +
                                   dbgIdName);
            break;
        case RetStat::ERROR_RESPONSE:
            status(SPDMStatus::Error_Responder);
            appContext.reportError("SPDM responder response fail on " +
                                   dbgIdName);
            break;
        case RetStat::ERROR_CERTIFICATE_CHAIN_DIGEST_INVALID:
        case RetStat::ERROR_ROOT_CERTIFICATE_HASH_INVALID:
        case RetStat::ERROR_CERTIFICATE_CHAIN_VERIFIY_FAILED:
        case RetStat::ERROR_CERTIFICATE_PARSING_ERROR:
        case RetStat::ERROR_CERTIFICATE_CHAIN_SIZE_INVALID:
            status(SPDMStatus::Error_CertificateValidation);
            appContext.reportError("SPDM certificate validation fail on " +
                                   dbgIdName);
            break;
        case RetStat::ERROR_AUTHENTICATION_FAILED:
            status(SPDMStatus::Error_AuthenticationFailed);
            appContext.reportError("SPDM authentication fail on " + dbgIdName);
            break;
        case RetStat::ERROR_MEASUREMENT_SIGNATURE_VERIFIY_FAILED:
            status(SPDMStatus::Error_MeasurementsSignatureVerificationFailed);
            appContext.reportError(
                "SPDM measurements signature verification fail on " +
                dbgIdName);
            break;
        case RetStat::ERROR_TIMEOUT:
            status(Responder::SPDMStatus::Error_ConnectionTimeout);
            appContext.reportError(
                "SPDM timeout on " + dbgIdName + ", while waiting on: " +
                get_cstr(connection.getDbgLastWaitState()) +
                ", timeout value: " +
                std::to_string(connection.getSendTimeoutValue()) + "ms");
            getLog().print("sendBuffer=");
            getLog().println(connection.getSendBufferRef());
            break;
        case RetStat::ERROR_INVALID_FLAG_SIZE:
        case RetStat::ERROR_INDICES_INVALID_SIZE:
        case RetStat::ERROR_WRONG_ALGO_BITS:
        case RetStat::ERROR_INVALID_PARAMETER:
        case RetStat::ERROR_INVALID_RESERVED:
            appContext.reportError("Packet corrupted on " + dbgIdName);
            break;
        default:
            status(SPDMStatus::Error_Other);
            appContext.reportError(std::string("SPDM other error: ") +
                                   get_cstr(rs) + " on " + dbgIdName);
    }
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

    ConnectionClass::SlotIdx slotidx =
        connection.getCurrentCertificateSlotIdx();

    /**
    This if else statement must be executed in a strictly consecutive (reverse)
    order to the SPDM protocol
    */
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
    else if (connection.hasInfo(ConnectionInfoEnum::CAPABILITIES))
    {
        updateCapabilities();
        status(SPDMStatus::GettingCertificates);
    }
    else if (connection.hasInfo(ConnectionInfoEnum::CHOOSEN_VERSION))
    {
        updateVersionInfo();
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
        auto& lg = getLog();
        lg.iprint("WARNING - refresh ignored because previous req: ");
        lg.iprint(connection.getWaitingForResponse());
        lg.iprint(" on eid: ");
        lg.iprint(eid);
        lg.iprint(" name: ");
        lg.iprint(inventoryPath.filename());
        lg.iprintln(" is still processing!");
        return;
    }

    // Need to first set initializing, because otherwise setting an error status
    // would not trigger a signal if the previous refresh set the same error.
    status(SPDMStatus::Initializing);

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
            if (ind < 255)
            {
                if (meas[ind])
                {
                    getLog().iprint("WARNING - duplicate measurement index: ");
                    getLog().println(ind);
                    status(SPDMStatus::Error_InvalidArguments);
                    return;
                }
                meas.set(ind);
            }
            else
            {
                getLog().iprint("WARNING - invalid measurement index value '");
                getLog().print(ind);
                getLog().println("' when specifying multiple indices!");
                status(SPDMStatus::Error_InvalidArguments);
                return;
            }
        }
    }

    eventHandler = &spdmd::dbus_api::Responder::handleEventForRefresh;

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
    auto rs = handleEventForRefresh(event);

    if (isError(rs) || (!event.is<EventReceiveClass>()))
    {
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
            // 0x02 "Hardware configuratigetBuson, such as straps, debug modes."
            setSerialNumberAsync(iter->second.ValueVector);
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
    lastUpdated(
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch())
            .count());
}

spdmcpp::RetStat MctpTransportClass::setupTimeout(spdmcpp::timeout_ms_t timeout)
{
    auto& io = responder.getAppCtx().getIo();
    if (!timer)
    {
        timer = std::make_unique<boost::asio::steady_timer>(io);
    }
    timer->expires_after(std::chrono::milliseconds(timeout));
    timer->async_wait([this](const boost::system::error_code& ec) {
        if (!ec)
        {
            timeoutCallback();
        }
    });
    return RetStat::OK;
}

void MctpTransportClass::timeoutCallback()
{
    spdmcpp::EventTimeoutClass ev(transportMedium);
    responder.handleEvent(ev);
}

bool MctpTransportClass::clearTimeout()
{
    if (timer)
    {
        boost::system::error_code ec;
        timer->cancel(ec);
        if (ec)
        {
            log.print("Failed to cancel the timer. Error=");
            log.println(ec.message());
        }
        return true;
    }
    return false;
}

void Responder::parseAndFillCertificate(const std::string& certPEM)
{
    auto resetCertificateProperties = [this]() {
        if (this->log.logLevel >= spdmcpp::LogClass::Level::Debug)
        {
            this->log.print(
                "parseAndFillCertificate: Resetting certificate properties for EID: ");
            this->log.println(this->eid);
        }
        certificateString("");
        issuer("");
        subject("");
        validNotBefore(0);
        validNotAfter(0);
        keyUsage({});
    };

    try
    {
        auto certInfo = ::parseCertificatePEM(this->log, certPEM);
        certificateString(certInfo.certificate);
        issuer(certInfo.issuer);
        subject(certInfo.subject);
        validNotBefore(certInfo.notBefore);
        validNotAfter(certInfo.notAfter);
        keyUsage(std::move(certInfo.keyUsage));
    }
    catch (const std::exception& e)
    {
        log.iprint("Certificate error for EID ");
        log.println(eid);
        log.iprint(e.what());
        log.println('\n');
        resetCertificateProperties();
    }
}

void Responder::setSerialNumberAsync(const std::vector<uint8_t>& serialData)
{
    const std::string propertyInterface =
        "xyz.openbmc_project.Inventory.Decorator.Asset";
    const std::string propertyName = "SerialNumber";
    auto propertyValue =
        std::variant<std::string>(toBigEndianHexString(serialData));

    const std::string path = std::string(inventoryPath);

    static constexpr auto mapperService = "xyz.openbmc_project.ObjectMapper";
    static constexpr auto mapperPath = "/xyz/openbmc_project/object_mapper";
    static constexpr auto mapperInterface = "xyz.openbmc_project.ObjectMapper";

    auto& conn = appContext.getConn();

    conn.async_method_call(
        [this, path, propertyInterface, propertyName, propertyValue](
            boost::system::error_code ec, sdbusplus::message::message& msg) {
            auto& log = getLog();
            std::map<std::string, std::vector<std::string>> mapperResponse;

            if (ec)
            {
                if (log.logLevel >= spdmcpp::LogClass::Level::Error)
                {
                    log.iprint(
                        "setSerialNumberAsync: Mapper GetObject error: ");
                    log.iprintln(ec.message());
                }
                return;
            }

            try
            {
                msg.read(mapperResponse);
            }
            catch (const std::exception& e)
            {
                if (log.logLevel >= spdmcpp::LogClass::Level::Error)
                {
                    log.iprint("setSerialNumberAsync parse mapper response: ");
                    log.iprintln(e.what());
                }
                return;
            }

            if (mapperResponse.empty())
            {
                if (log.logLevel >= spdmcpp::LogClass::Level::Error)
                {
                    log.iprint(
                        "setSerialNumberAsync: No service found for path: ");
                    log.iprintln(path);
                }
                return;
            }

            const auto& service = mapperResponse.begin()->first;
            static constexpr auto dbusPropertiesIface =
                "org.freedesktop.DBus.Properties";
            static constexpr auto methodSet = "Set";

            auto& conn = appContext.getConn();
            conn.async_method_call(
                [this, path](boost::system::error_code ecSet) {
                    auto& log = getLog();
                    if (ecSet)
                    {
                        if (log.logLevel >= spdmcpp::LogClass::Level::Error)
                        {
                            log.iprint(
                                "Error setting serial number for path: ");
                            log.iprint(path);
                            log.iprint(" error: ");
                            log.iprintln(ecSet.message());
                        }
                    }
                },
                service, path, dbusPropertiesIface, methodSet,
                propertyInterface, propertyName, propertyValue);
        },
        mapperService, mapperPath, mapperInterface, "GetObject", path,
        std::vector<std::string>{propertyInterface});
}

} // namespace dbus_api
} // namespace spdmd
