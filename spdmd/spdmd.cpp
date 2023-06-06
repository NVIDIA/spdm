#include "mctp_endpoint_discovery.hpp"
#include "spdmcpp/common.hpp"
#include "spdmd_app.hpp"
#include "spdmd_version.hpp"

#include <bits/stdc++.h>

#include <CLI/CLI.hpp>

#include <string>

using namespace std;
using namespace spdmd;
using namespace sdbusplus;

// Define the SPDM default dbus path location for objects.
constexpr auto spdmRootObjectPath = "/xyz/openbmc_project/SPDM";
constexpr auto spdmDefaultService = "xyz.openbmc_project.SPDM";

namespace spdmd
{

dbus::ServiceHelper inventoryService("/", "org.freedesktop.DBus.ObjectManager",
                                     "xyz.openbmc_project.PLDM");


SpdmdApp::SpdmdApp() :
    SpdmdAppContext(sdeventplus::Event::get_default(),
#ifdef USE_DEFAULT_DBUS
                    bus::new_default(),
#else
                    bus::new_system(),
#endif
                    std::cout
                )
    , mctpIoPCIe(getLog()), mctpIoSPI(getLog()), mctpIoI2C(getLog())
{
    context.registerIo(mctpIoPCIe, spdmcpp::TransportMedium::PCIe);
    context.registerIo(mctpIoSPI, spdmcpp::TransportMedium::SPI);
    context.registerIo(mctpIoI2C, spdmcpp::TransportMedium::I2C);
}


SpdmdApp::~SpdmdApp()
{
    try
    {
        context.unregisterIo(mctpIoPCIe, spdmcpp::TransportMedium::PCIe);
        context.unregisterIo(mctpIoSPI, spdmcpp::TransportMedium::SPI);
        context.unregisterIo(mctpIoI2C, spdmcpp::TransportMedium::I2C);
        delete mctpEventPCIe;
        delete mctpEventSPI;
        delete mctpEventI2C;
    }
    catch(const std::exception& exc)
    {
        std::cerr << "Unhandled exception when destroying spdmd " <<
            exc.what() << std::endl;
    }
}



void SpdmdApp::setupCli(int argc, char** argv)
{
    CLI::App app{spdmd::description::name + ", version " +
                 spdmd::description::version};

    CLI::Option* opt =
        app.add_option("-v, --verbose", verbose, "Verbose log level (0-7)");
    opt->check(CLI::Range(0, 7));

    std::vector<std::string> cache;
    opt = app.add_option(
        "--cached_measurements", cache,
        "[all | eid0, eid1,...] Enables automatic getting of measurements for all devices or the listed EIDs upon discovery but no quicker than '--cached_measurements_delay' seconds after launch.");
    opt->delimiter(',');
    opt->check(CLI::IsMember({"all"}) | CLI::Range(1, 254));

    app.add_option(
        "--cached_measurements_delay", measureOnDiscoveryDelay,
        "[seconds]; The initial communication should be performed after running the daemon with a delay configured by this param. Default value: 60.");

    try
    {
        (app).parse((argc), (argv));
    }
    catch (const CLI::ParseError& e)
    {
        exit((app).exit(e));
    }

    if (verbose > spdmcpp::LogClass::Level::Emergency)
    {
        getLog().setLogLevel(verbose);
        getLog().print("Verbose log level set to " +
                       obmcprj::Logging::server::convertForMessage(
                           (obmcprj::Logging::server::Entry::Level)verbose) +
                       "\n");
    }
    else
    {
        getLog().setLogLevel(spdmcpp::LogClass::Level::Error);
    }

    if (!cache.empty())
    {
        measureOnDiscovery = true;
        if (measureOnDiscoveryDelay == std::chrono::seconds(0))
        {
            measureOnDiscoveryActive = true;
            // initial mctp discovery happens early on so if delay is 0 we need
            // to enable this already here
        }
        if (!(cache.size() == 1 && cache[0] == "all"))
        {
            try
            {
                for (auto& i : cache)
                {
                    cachedMeasurements.insert(std::stoi(i));
                }
            }
            catch (const std::invalid_argument& e)
            {
                throw std::invalid_argument(
                    "--cached_measurements: 'all' can only be used alone, without other EID numbers");
            }
        }
    }
}

void SpdmdApp::connectDBus()
{
    SPDMCPP_LOG_TRACE_FUNC(getLog());
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
}


void SpdmdApp::connectMCTP()
{
    SPDMCPP_LOG_TRACE_FUNC(getLog());
    if (!mctpIoPCIe.isSocketOpen())
    {
        if (mctpIoPCIe.createSocket("\0mctp-pcie-mux"s))
        {
            auto callback = [this](sdeventplus::source::IO& /*io*/, int /*fd*/,
                            uint32_t revents) {
                mctpCallback(revents, mctpIoPCIe);
            };
            mctpEventPCIe = new sdeventplus::source::IO(event, mctpIoPCIe.getSocket(), EPOLLIN,
                                                    std::move(callback));
        } else {
            if (getLog().logLevel >= spdmcpp::LogClass::Level::Warning) {
                getLog().iprintln("Unable to connect to mctp-pcie-mux socket");
            }
        }
    }
    if (!mctpIoSPI.isSocketOpen())
    {
        if (mctpIoSPI.createSocket("\0mctp-spi-mux"s))
        {
            auto callback = [this](sdeventplus::source::IO& /*io*/, int /*fd*/,
                            uint32_t revents) {
                mctpCallback(revents, mctpIoSPI);
            };
            mctpEventSPI = new sdeventplus::source::IO(event, mctpIoSPI.getSocket(), EPOLLIN,
                                                    std::move(callback));
        } else {
            if (getLog().logLevel >= spdmcpp::LogClass::Level::Warning) {
                getLog().iprintln("Unable to connect to mctp-spi-mux socket");
            }
        }
    }


#ifdef USE_I2C
    if (!mctpIoI2C.isSocketOpen())
    {
        if (mctpIoI2C.createSocket("\0mctp-i2c-mux"s))
        {
            auto callback = [this](sdeventplus::source::IO& /*io*/, int /*fd*/,
                            uint32_t revents) {
                mctpCallback(revents, mctpIoI2C);
            };
            mctpEventI2C = new sdeventplus::source::IO(event, mctpIoI2C.getSocket(), EPOLLIN,
                                                       std::move(callback));

        } else {
            if (getLog().logLevel >= spdmcpp::LogClass::Level::Warning) {
                getLog().iprintln("Unable to connect to mctp-i2c-mux socket");
            }
        }
    }
#endif

#ifdef USE_I2C
    if(!mctpEventPCIe && !mctpEventSPI && !mctpEventI2C) {
#else
    if(!mctpEventPCIe && !mctpEventSPI) {
#endif
        throw std::runtime_error("Couldn't connect to any MCTP endpoint");
    }
}



bool SpdmdApp::needRecreateResponder(spdmcpp::TransportMedium currMedium,
                                     spdmcpp::TransportMedium newMedium)
{
    using tran = spdmcpp::TransportMedium;
    switch (currMedium)
    {
        case tran::PCIe:
            return false;
        case tran::SPI:
            return newMedium == tran::PCIe;
        case tran::I2C:
            return newMedium != tran::I2C;
    }
    return false;
}

void SpdmdApp::discoveryUpdateResponder(const dbus_api::ResponderArgs& respArg)
{

    const auto it = resp_discovery.find(respArg.uuid);
    if (it == std::end(resp_discovery))
    {
        // Discovery object by UUID not found select first
        resp_discovery.emplace(std::make_pair(respArg.uuid, respArg));
        createResponder(respArg);
        reportNotice("Create first responder UUID: " + respArg.uuid +
                     " EID: " + std::to_string(respArg.eid));
    }
    else
    {
        // Discovery found recreate if needed
        if (respArg.medium.has_value() && it->second.medium.has_value())
        {
            if (needRecreateResponder(it->second.medium.value(),
                                      respArg.medium.value()))
            {
                reportNotice("Recreate responder UUID: " + respArg.uuid +
                             " EID: " + std::to_string(respArg.eid));
                responders[it->second.eid].reset();
                resp_discovery.emplace(std::make_pair(respArg.uuid, respArg));
                createResponder(respArg);
            }
            else
            {
                reportNotice("Lower priority responder not need create: " +
                             it->first);
            }
        }
        else
        {
            reportNotice("Unknown transport medium when recreate: " +
                         it->first);
        }
    }
}

void SpdmdApp::createResponder(const dbus_api::ResponderArgs& args)
{
    SPDMCPP_LOG_TRACE_FUNC(getLog());
    if (args.eid >= responders.size())
    {
        responders.resize(args.eid + 1);
    }

    string msg = "Creating SPDM object for a responder with EID = " +
                 to_string(args.eid);
    reportNotice(msg);

    std::string path(spdmRootObjectPath);
    { // construct responder path
        path += '/';
        auto sub = args.inventoryPath.filename();
        if (!sub.empty())
        {
            path += sub;
        }
        else
        { // fallback to eid for local-testing
            path += std::to_string(args.eid);
        }
    }
    if(args.medium.has_value()) {
        responders[args.eid] = std::make_unique<dbus_api::Responder>(
            *this, path, args.eid, args.mctpPath, args.inventoryPath, args.medium.value_or(TransportMedium::PCIe));
    } else {
        reportError("Unable to determine responder type for EID = " + std::to_string(args.eid) );
    }

#if FETCH_SERIALNUMBER_FROM_RESPONDER != 0
    responders[args.eid]->refreshSerialNumber();
#endif
    autoMeasure(args.eid);
}

void SpdmdApp::setupMeasurementDelay()
{
    if (!measureOnDiscovery)
    {
        return;
    }
    if (measureOnDiscoveryDelay == std::chrono::seconds(0))
    {
        // measureOnDiscoveryActive should've already been set,
        // because initial discovery happens earlier
        SPDMCPP_ASSERT(measureOnDiscoveryActive);
        return;
    }
    auto timerCallback = [this](Timer& /*source*/, Timer::TimePoint /*time*/) {
        measurementDelayCallback();
    };
    measurementDelayTimer = make_unique<Timer>(
        event, SpdmdAppContext::Clock(event).now() + measureOnDiscoveryDelay,
        std::chrono::seconds{1}, std::move(timerCallback));
}



void SpdmdApp::mctpCallback(uint32_t revents, spdmcpp::MctpIoClass &mctpIo)
{

        SPDMCPP_LOG_TRACE_FUNC(getLog());

        if (!(revents & EPOLLIN))
        {
            return;
        }

        {
            auto rs = mctpIo.read(packetBuffer);
            if (rs != spdmcpp::RetStat::OK)
            {
                getLog().println(
                    "SpdmdApp::IO read failed likely due to broken socket connection, quitting!");
                event.exit(1);
                return;
            }
        }

        uint8_t eid = 0;
        {
            spdmcpp::TransportClass::LayerState lay; // TODO double decode
            auto rs =
                spdmcpp::MctpTransportClass::peekEid(packetBuffer, lay, eid);

            SPDMCPP_LOG_TRACE_RS(getLog(), rs);
            switch (rs)
            {
                case spdmcpp::RetStat::OK:
                    break;
                case spdmcpp::RetStat::ERROR_BUFFER_TOO_SMALL:
                    getLog().print("SpdmdApp::IO: packet size = ");
                    getLog().print(packetBuffer.size());
                    getLog().println(" is too small to be a valid SPDM packet");
                    return;
                default:
                    getLog().print(
                        "SpdmdApp::IO peekEid returned unexpected error: ");
                    getLog().println(rs);
                    return;
            }
        }
        if (eid >= responders.size())
        {
            getLog().println("SpdmdApp::IO received message from EID=" +
                             std::to_string(eid) +
                             " outside of responder array size=" +
                             std::to_string(responders.size()));
            return;
        }
        if (!responders[eid])
        {
            getLog().println("SpdmdApp::IO received message from EID=" +
                             std::to_string(eid) +
                             " while responder class is not created");
        }
        else
        {
            auto& resp = responders[eid];
            spdmcpp::EventReceiveClass ev(packetBuffer);
            resp->handleEvent(ev);
        }
}




void SpdmdApp::measurementDelayCallback()
{
    measureOnDiscoveryActive = true;
    for (size_t eid = 0; eid < responders.size(); ++eid)
    {
        if (responders[eid])
        {
            autoMeasure(eid);
        }
    }
}

bool SpdmdApp::autoMeasure(uint8_t eid) const
{
    if (!shouldMeasureEID(eid))
    {
        return false;
    }
    responders[eid]->refresh(0, std::vector<uint8_t>(), std::vector<uint8_t>(),
                             0);
    return true;
}

int SpdmdApp::loop()
{
    return event.loop();
}


}

int main(int argc, char** argv)
{
    int returnCode = 0;

    try
    {
        SpdmdApp spdmApp;

        spdmApp.setupCli(argc, argv);

        spdmApp.connectDBus();

        std::unique_ptr<MctpDiscovery> mctpDiscoveryHandler =
            std::make_unique<MctpDiscovery>(spdmApp);

        spdmApp.setupMeasurementDelay();

        auto& bus = spdmApp.getBus();
        sdbusplus::server::manager_t objManager(bus, spdmRootObjectPath);
        bus.request_name(spdmDefaultService);

        returnCode = spdmApp.loop();
    }
    catch (const std::exception& e)
    {
        std::cerr << "exception reached main '" << e.what() << std::endl;
        returnCode = -2;
    }

    return returnCode;
}
