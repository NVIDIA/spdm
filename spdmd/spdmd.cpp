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
//using namespace spdm::responder;

int SPDMD_SetupCli(int argc, char** argv)
{
	int verbose{0};
	spdmcpp::LogClass Log(cout);

    CLI::App app{spdmd::description::NAME + ", version " + spdmd::description::VERSION};

	CLI::Option* opt_verbosity = app.add_option("-v, --verbose", verbose, "Verbose level (0-3)");
	opt_verbosity->check(CLI::Range(0,3));

    CLI11_PARSE(app, argc, argv);
	
	if (verbose) {
		Log.print("Verbose level set to ");
		Log.println(verbose);
	}

	return verbose;
}

int main(int argc, char** argv)
{
	spdmcpp::LogClass Log(cout);
	int verbose = SPDMD_SetupCli(argc, argv);

    auto& bus = spdmd::utils::DBusHandler::getBus();
    sdbusplus::server::manager::manager objManager(
        bus, "/xyz/openbmc_project/software");
    //dbus_api::Responder dbusImplReq(bus, "/xyz/openbmc_project/spdm");

	if (verbose) {
		Log.println(spdmd::description::NAME + " finishes");
	}

	return 0;
}
