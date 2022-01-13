#include <CLI/CLI.hpp>

int main(int argc, char** argv)
{
    CLI::App app{"SPDM deamon for OpenBMC"};
    app.require_subcommand(1)->ignore_case();

//    spdmd::base::registerCommand(app);

    CLI11_PARSE(app, argc, argv);
	
//	if (verbose) {//TODO shutup a warning
//	}

	return 0;
}
