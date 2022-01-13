#include <bits/stdc++.h>
#include <string>

#include <CLI/CLI.hpp>

#include "spdmcpp/log.hpp"
#include "spdmd_version.hpp"

using namespace std;

int main(int argc, char** argv)
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

	return 0;
}
