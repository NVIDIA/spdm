
#include <iostream>

// #include "common/utils.hpp"
// #include "dbus_impl_requester.hpp"
// #include "host-bmc/host_condition.hpp"
// #include "invoker.hpp"
// #include "requester/handler.hpp"
// #include "requester/request.hpp"

#include <err.h>
#include <getopt.h>
#include <poll.h>
#include <stdlib.h>
#include <sysexits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <sdeventplus/event.hpp>
#include <sdeventplus/source/io.hpp>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

void optionUsage(void)
{
    std::cerr << "Usage: spdmcppd [options]\n";
    std::cerr << "Options:\n";
    std::cerr
        << "  --verbose=<0/1>  0 - Disable verbosity, 1 - Enable verbosity\n";
    std::cerr << "Defaulted settings:  --verbose=0 \n";
}

int main(int argc, char** argv)
{
	std::cout << "blabla\n";

	bool verbose = false;
	static struct option long_options[] = {
		{"verbose", required_argument, nullptr, 'v'},
		{nullptr, 0, nullptr, 0}
	};

	for (;;) {
		auto argflag = getopt_long(argc, argv, "v:", long_options, nullptr);

		if (argflag == -1)
			break;

		switch (argflag)
		{
		case 'v':
			switch (std::stoi(optarg))
			{
				case 0:
					verbose = false;
					break;
				case 1:
					verbose = true;
					break;
				default:
					optionUsage();
					exit(EX_USAGE);
			}
			break;

		default:
			optionUsage();
			exit(EX_USAGE);
		}
	}
	
	if (verbose) {//TODO shutup a warning
	}

	return 0;
}
