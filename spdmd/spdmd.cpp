#include <bits/stdc++.h>
#include <string>

#include <CLI/CLI.hpp>
#include <sdeventplus/event.hpp>
#include <sdeventplus/source/io.hpp>

#include "spdmcpp/log.hpp"
#include "spdmd_version.hpp"
#include "utils.hpp"
#include "dbus_impl_responder.hpp"

using namespace std;
using namespace spdmd;
using namespace sdeventplus;
using namespace sdeventplus::source;
using namespace sdbusplus;
//using namespace spdm::responder;

// Define the SPDM default dbus path location for objects.
constexpr auto SPDM_DEFAULT_PATH = "/xyz/openbmc_project/SPDM";
constexpr auto SPDM_DEFAULT_SERVICE = "xyz.openbmc_project.SPDM";

class SpdmdApp
{
  public:
	int verbose{0};
	spdmcpp::LogClass Log;	
		
	SpdmdApp() : Log(std::cout)
	{
	}
	~SpdmdApp()
	{
	}

	int SPDMD_SetupCli(int argc, char** argv)
	{
		CLI::App app{spdmd::description::NAME + ", version " + spdmd::description::VERSION};

		CLI::Option* opt_verbosity = app.add_option("-v, --verbose", verbose, "Verbose level (0-3)");
		opt_verbosity->check(CLI::Range(0,3));

		CLI11_PARSE(app, argc, argv);
		
		if (verbose) {
			Log.print("Verbose level set to ");
			Log.println(verbose);
		}

		return 0;
	}

	void dbg(const char* debug)
	{
		if (verbose > 0)
		{
			Log.println(debug);
		}
	}

	void dbg(const std::string& debug)
	{
		if (verbose > 0)
		{
			Log.println(debug);
		}
	}
};

int main(int argc, char** argv)
{
	/* 1. Setup log, CLI */
	SpdmdApp spdmApp;
	spdmApp.SPDMD_SetupCli(argc, argv);

    /* 2. Create SPDM default dbus service */
	//auto event = Event::get_default();
    auto& bus = utils::DBusHandler::getBus();
    sdbusplus::server::manager_t objManager(bus, SPDM_DEFAULT_PATH);
    bus.request_name(SPDM_DEFAULT_SERVICE);
	//bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);

    /* 3. Get list of SPDM connected devices available at MCTP */

	/* 4. Create SPDM object for each SPDM responder */
	dbus_api::Responder dbusImplReq{bus, SPDM_DEFAULT_PATH};

	/* 5. Enter forever loop */
    //int returnCode = event.loop();
    // Handle dbus processing forever.
    while (1)
    {
        bus.process_discard(); // discard any unhandled messages
        bus.wait();
    }

	//spdmApp.dbg(spdmd::description::NAME + " finishes with ret code " + to_string(returnCode));
	
	//if (returnCode)
    //{
    //    exit(EXIT_FAILURE);
    //}

    exit(EXIT_SUCCESS);
}
