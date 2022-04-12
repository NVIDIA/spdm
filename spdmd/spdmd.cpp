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

SpdmdApp::SpdmdApp() :
    SpdmdAppContext(sdeventplus::Event::get_default(), bus::new_system(),
                    std::cout),
    mctpIo(getLog())
{}

SpdmdApp::~SpdmdApp()
{
    delete mctpEvent;
}

void SpdmdApp::setupCli(int argc, char** argv)
{
    CLI::App app{spdmd::description::name + ", version " +
                 spdmd::description::version};

    CLI::Option* optVerbosity =
        app.add_option("-v, --verbose", verbose, "Verbose log level (0-7)");
    optVerbosity->check(CLI::Range(0, 7));

    app.parse(argc, argv);

    if (verbose > spdmcpp::LogClass::Level::Emergency)
    {
        log.setLogLevel(verbose);
        log.print("Verbose log level set to " +
                  Logging::server::convertForMessage(
                      (Logging::server::Entry::Level)verbose) +
                  "\n");
    }
}

void SpdmdApp::connectDBus()
{
    SPDMCPP_LOG_TRACE_FUNC(log);
    sdbusplus::server::manager_t objManager(bus, spdmRootObjectPath);
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    bus.request_name(spdmDefaultService);
}

void SpdmdApp::connectMCTP()
{
    SPDMCPP_LOG_TRACE_FUNC(log);
    if (!mctpIo.createSocket())
    {
        throw std::runtime_error("Couldn't create mctp socket");
    }

    context.registerIo(&mctpIo);

    auto callback = [this](sdeventplus::source::IO& /*io*/, int /*fd*/,
                           uint32_t revents) {
        SPDMCPP_LOG_TRACE_FUNC(log);

        if (!(revents & EPOLLIN))
        {
            return;
        }

        mctpIo.read(packetBuffer);

        uint8_t eid = 0;
        {
            spdmcpp::TransportClass::LayerState lay; // TODO double decode
            auto rs =
                spdmcpp::MctpTransportClass::peekEid(packetBuffer, lay, eid);

            SPDMCPP_LOG_TRACE_RS(log, rs);
            if (rs != spdmcpp::RetStat::OK)
            {
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
            resp->handleRecv(packetBuffer);
        }
    };

    mctpEvent = new sdeventplus::source::IO(event, mctpIo.Socket, EPOLLIN,
                                            std::move(callback));
}

void SpdmdApp::createResponder(uint8_t eid, const std::string& inventoryPath)
{
    SPDMCPP_LOG_TRACE_FUNC(log);
    if (eid >= responders.size())
    {
        responders.resize(eid + 1);
    }

    if (responders[eid])
    {
        std::string msg("responder for EID" + to_string(eid) +
                        " already exists!");
        log.iprint("Error: ");
        log.println(msg);
        throw std::invalid_argument(msg);
    }

    string msg =
        "Creating SPDM object for a responder with EID = " + to_string(eid);
    reportNotice(msg);

    responders[eid] =
        new dbus_api::Responder(*this, spdmRootObjectPath, eid, inventoryPath);
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

        spdmApp.connectMCTP();

        std::unique_ptr<MctpDiscovery> mctpDiscoveryHandler =
            std::make_unique<MctpDiscovery>(spdmApp);

        returnCode = spdmApp.loop();
    }
    catch (const std::exception& e)
    {
        std::cerr << "exception reached main '" << e.what() << std::endl;
        returnCode = -2;
    }

    return returnCode;
}
