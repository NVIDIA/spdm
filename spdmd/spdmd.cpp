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
constexpr auto SPDM_DEFAULT_PATH = "/xyz/openbmc_project/SPDM";
constexpr auto SPDM_DEFAULT_SERVICE = "xyz.openbmc_project.SPDM";

namespace spdmd
{

SpdmdApp::SpdmdApp() :
    SpdmdAppContext(sdeventplus::Event::get_default(), bus::new_system(),
                    std::cout),
    mctpIo(getLog())
{}

SpdmdApp::~SpdmdApp()
{
    delete mctpEvent;
}

int SpdmdApp::setupCli(int argc, char** argv)
{
    CLI::App app{spdmd::description::NAME + ", version " +
                 spdmd::description::VERSION};

    CLI::Option* opt_verbosity =
        app.add_option("-v, --verbose", verbose, "Verbose log level (0-7)");
    opt_verbosity->check(CLI::Range(0, 7));

    CLI11_PARSE(app, argc, argv);

    if (verbose > spdmcpp::LogClass::Level::Emergency)
    {
        log.SetLogLevel(verbose);
        log.print("Verbose log level set to " +
                  Logging::server::convertForMessage(
                      (Logging::server::Entry::Level)verbose) +
                  "\n");
    }

    return 0;
}

void SpdmdApp::connectDBus()
{
    SPDMCPP_LOG_TRACE_FUNC(log);
    sdbusplus::server::manager_t objManager(bus, SPDM_DEFAULT_PATH);
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    bus.request_name(SPDM_DEFAULT_SERVICE);
}

bool SpdmdApp::connectMCTP()
{
    SPDMCPP_LOG_TRACE_FUNC(log);
    if (!mctpIo.createSocket())
        return false;

    context.register_io(&mctpIo);

    auto callback = [this](sdeventplus::source::IO& /*io*/, int /*fd*/,
                           uint32_t revents) {
        SPDMCPP_LOG_TRACE_FUNC(log);
        // 			spdmcpp::LogClass& log = Connection->getLog();
        // 			log.iprintln("Event recv!");

        if (!(revents & EPOLLIN))
        {
            return;
        }

        //	context.IO->read(packetBuffer);
        mctpIo.read(packetBuffer);

        uint8_t eid = 0;
        {
            spdmcpp::TransportClass::LayerState lay; // TODO double decode
            auto rs =
                spdmcpp::MCTP_TransportClass::peek_eid(packetBuffer, lay, eid);

            SPDMCPP_LOG_TRACE_RS(log, rs);
            if (rs != spdmcpp::RetStat::OK)
            {
                // TODO just log warning and ignore message?!
                event.exit(1);
            }
        }
        if (eid >= responders.size())
        {
            // TODO just log warning and ignore message?!
            event.exit(1);
        }
        auto resp = responders[eid];
        if (!resp)
        {
            // TODO just log warning and ignore message?!
            event.exit(1);
        }
        resp->handleRecv(packetBuffer);
    };

    mctpEvent = new sdeventplus::source::IO(event, mctpIo.Socket, EPOLLIN,
                                            std::move(callback));

    return true;
}

bool SpdmdApp::createResponder(uint8_t eid, const std::string& inventory_path)
{
    SPDMCPP_LOG_TRACE_FUNC(log);
    if (eid >= responders.size())
    {
        responders.resize(eid + 1);
    }

    if (responders[eid])
    {
        log.iprint("Error: responder for eid ");
        log.print(eid);
        log.println(" already exists!");
        return false;
    }

    string msg =
        "Creating SPDM object for a responder with EID = " + to_string(eid);
    reportNotice(msg);

    responders[eid] =
        new dbus_api::Responder(*this, SPDM_DEFAULT_PATH, eid, inventory_path);

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

    SpdmdApp spdmApp;

    spdmApp.setupCli(argc, argv);

    spdmApp.connectDBus();

    if (spdmApp.connectMCTP())
    {
        std::unique_ptr<MctpDiscovery> mctpDiscoveryHandler =
            std::make_unique<MctpDiscovery>(spdmApp);

        returnCode = spdmApp.loop();
    }

    return returnCode;
}
