#include "dbus_impl_responder.hpp"
#include "spdmcpp/log.hpp"
#include "spdmd_version.hpp"
#include "utils.hpp"

#include <bits/stdc++.h>

#include <CLI/CLI.hpp>

#include <string>

using namespace std;
using namespace spdmd;
// using namespace sdeventplus;
// using namespace sdeventplus::source;
using namespace sdbusplus;
// using namespace spdm::responder;

// Define the SPDM default dbus path location for objects.
constexpr auto SPDM_DEFAULT_PATH = "/xyz/openbmc_project/SPDM";
constexpr auto SPDM_DEFAULT_SERVICE = "xyz.openbmc_project.SPDM";

class SpdmdApp : public ResponderContext
{
  public:
    int verbose{0};
    spdmcpp::LogClass log;

    SpdmdApp() :
        ResponderContext(sdeventplus::Event::get_default(), bus::new_default()),
        log(std::cout), MCTPIO(log)
    {}
    ~SpdmdApp()
    {
        delete MCTPEvent;
    }

    int SPDMD_SetupCli(int argc, char** argv)
    {
        CLI::App app{spdmd::description::NAME + ", version " +
                     spdmd::description::VERSION};

        CLI::Option* opt_verbosity =
            app.add_option("-v, --verbose", verbose, "Verbose level (0-3)");
        opt_verbosity->check(CLI::Range(0, 3));

        CLI11_PARSE(app, argc, argv);

        if (verbose)
        {
            log.print("Verbose level set to ");
            log.println(verbose);
        }

        return 0;
    }

    void connectDBus()
    {
        sdbusplus::server::manager_t objManager(bus, SPDM_DEFAULT_PATH);
        bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
        bus.request_name(SPDM_DEFAULT_SERVICE);
    }

    bool connectMCTP()
    {
        SPDMCPP_LOG_TRACE_FUNC(log);
        if (!MCTPIO.createSocket())
            return false;

        context.register_io(&MCTPIO);

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
            MCTPIO.read(packetBuffer);

            uint8_t eid = 0;
            {
                spdmcpp::TransportClass::LayerState lay; // TODO double decode
                auto rs = spdmcpp::MCTP_TransportClass::peek_eid(packetBuffer,
                                                                 lay, eid);

                SPDMCPP_LOG_TRACE_RS(log, rs);
                if (rs != spdmcpp::RetStat::OK)
                {
                    // TODO just log warning and ignore message?!
                    event.exit(1);
                }
            }
            if (eid >= Responders.size())
            {
                // TODO just log warning and ignore message?!
                event.exit(1);
            }
            auto resp = Responders[eid];
            if (!resp)
            {
                // TODO just log warning and ignore message?!
                event.exit(1);
            }
            resp->handleRecv(packetBuffer);
        };

        MCTPEvent = new sdeventplus::source::IO(event, MCTPIO.Socket, EPOLLIN,
                                                std::move(callback));

        return true;
    }

    bool createResponder(uint8_t eid)
    {
        SPDMCPP_LOG_TRACE_FUNC(log);
        if (eid >= Responders.size())
        {
            Responders.resize(eid + 1);
        }
        if (Responders[eid])
        {
            log.iprint("Error: responder for eid ");
            log.print(eid);
            log.println(" already exists!");
            return false;
        }
        Responders[eid] =
            new dbus_api::Responder(*this, SPDM_DEFAULT_PATH, eid);
        return true;
    }

    int loop()
    {
        return event.loop();
    }

    void dbg(const char* debug)
    {
        if (verbose > 0)
        {
            log.println(debug);
        }
    }

    void dbg(const std::string& debug)
    {
        if (verbose > 0)
        {
            log.println(debug);
        }
    }

  private:
    spdmcpp::MCTP_IOClass MCTPIO;
    sdeventplus::source::IO* MCTPEvent = nullptr;
    std::vector<dbus_api::Responder*> Responders;
    std::vector<uint8_t> packetBuffer;
};

int main(int argc, char** argv)
{
    /* 1. Setup log, CLI */
    SpdmdApp spdmApp;
    spdmApp.SPDMD_SetupCli(argc, argv);

    spdmApp.connectDBus();

    if (!spdmApp.connectMCTP())
    {
        return -1;
    }

    /* 2. Get list of SPDM connected devices available at MCTP */

    /* 3. Create SPDM object for each SPDM responder */
    //	dbus_api::Responder dbusImplReq{bus, SPDM_DEFAULT_PATH, 14};

    spdmApp.createResponder(14);
    spdmApp.createResponder(16);

    /* 4. Enter forever loop */
    int returnCode = spdmApp.loop();

    spdmApp.dbg(spdmd::description::NAME + " finishes with ret code " +
                to_string(returnCode));

    return returnCode;
}
