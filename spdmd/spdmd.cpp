#include "mctp_endpoint_discovery.hpp"
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

dbus::ServiceHelper inventoryService("/xyz/openbmc_project/inventory",
                                     "org.freedesktop.DBus.ObjectManager",
                                     "xyz.openbmc_project.PLDM");

SpdmdApp::SpdmdApp() :
    SpdmdAppContext(sdeventplus::Event::get_default(), bus::new_system(),
                    std::cout),
    mctpIo(getLog())
{
    context.registerIo(mctpIo);
}

SpdmdApp::~SpdmdApp()
{
    context.unregisterIo(mctpIo);

    delete mctpEvent;
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
        log.setLogLevel(verbose);
        log.print("Verbose log level set to " +
                  Logging::server::convertForMessage(
                      (Logging::server::Entry::Level)verbose) +
                  "\n");
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
    SPDMCPP_LOG_TRACE_FUNC(log);
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
}

void SpdmdApp::connectMCTP()
{
    SPDMCPP_LOG_TRACE_FUNC(log);
    if (!mctpIo.createSocket())
    {
        throw std::runtime_error("Couldn't create mctp socket");
    }

    auto callback = [this](sdeventplus::source::IO& /*io*/, int /*fd*/,
                           uint32_t revents) {
        SPDMCPP_LOG_TRACE_FUNC(log);

        if (!(revents & EPOLLIN))
        {
            return;
        }

        {
            auto rs = mctpIo.read(packetBuffer);
            if (rs != spdmcpp::RetStat::OK) {
                log.println("SpdmdApp::IO read failed likely due to broken socket connection, quitting!");
                event.exit(1);
                return;
            }
        }

        uint8_t eid = 0;
        {
            spdmcpp::TransportClass::LayerState lay; // TODO double decode
            auto rs =
                spdmcpp::MctpTransportClass::peekEid(packetBuffer, lay, eid);

            SPDMCPP_LOG_TRACE_RS(log, rs);
            switch (rs) {
            case spdmcpp::RetStat::OK:
                break;
            case spdmcpp::RetStat::ERROR_BUFFER_TOO_SMALL:
                log.print("SpdmdApp::IO: packet size = ");
                log.print(packetBuffer.size());
                log.println(" is too small to be a valid SPDM packet");
                return;
            default:
                log.print("SpdmdApp::IO peekEid returned unexpected error: ");
                log.println(rs);
                return;
            }
        }
        if (eid >= responders.size())
        {
            log.println("SpdmdApp::IO received message from EID=" +
                        std::to_string(eid) +
                        " outside of responder array size=" +
                        std::to_string(responders.size()));
            return;
        }
        auto resp = responders[eid];
        if (!resp)
        {
            log.println("SpdmdApp::IO received message from EID=" +
                        std::to_string(eid) +
                        " while responder class is not created");
        }
        else
        {
            spdmcpp::EventReceiveClass ev(packetBuffer);
            resp->handleEvent(ev);
        }
    };

    mctpEvent = new sdeventplus::source::IO(event, mctpIo.getSocket(), EPOLLIN,
                                            std::move(callback));
}

void SpdmdApp::createResponder(
    uint8_t eid, const sdbusplus::message::object_path& mctpPath,
    const sdbusplus::message::object_path& inventoryPath)
{
    SPDMCPP_LOG_TRACE_FUNC(log);
    if (eid >= responders.size())
    {
        responders.resize(eid + 1);
    }

    if (responders[eid])
    {
        // The device is already created.
        // It's been decided this is not an error and should be silently
        // ignored. In part because it happens when pldmd is restarted.
        // In general device removal and hot-plug is not supported by pldm or
        // spdm.
        return;
    }

    string msg =
        "Creating SPDM object for a responder with EID = " + to_string(eid);
    reportNotice(msg);

    std::string path(spdmRootObjectPath);
    { // construct responder path
        path += '/';
        auto sub = inventoryPath.filename();
        if (!sub.empty())
        {
            path += sub;
        }
        else
        { // fallback to eid for local-testing
            path += std::to_string(eid);
        }
    }
    responders[eid] =
        new dbus_api::Responder(*this, path, eid, mctpPath, inventoryPath);

#if FETCH_SERIALNUMBER_FROM_RESPONDER != 0
    responders[eid]->refreshSerialNumber();
#endif
    autoMeasure(eid);
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

} // namespace spdmd

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
