#include <iostream>
#include <spdm_tool.hpp>

// Tool main looop
auto main(int argc, char** argv) -> int
{
    try
    {
        spdmt::SpdmTool app;
        // Parse arguments
        if(app.parseArgs(argc, argv)) {
            return EXIT_FAILURE;
        }
        // Run application
        if(!app.run()) {
            return EXIT_FAILURE;
        }
    }
    catch(const std::exception& exc)
    {
        std::cerr << "Unhandled exception " << exc.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
