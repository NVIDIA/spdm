#pragma once

#include "libspdmcpp/headers_public/spdmcpp/flag.hpp"

#include "spdm_fuzzer_config.hpp"
#include "spdm_fuzzer_predefined_responses.hpp"

namespace spdm_wrapper
{
class SpdmWrapperApp
{
  public:
    void setupCli(int argc, char** argv);
    bool run(spdmcpp::BaseAsymAlgoFlags asymAlgo, spdmcpp::BaseHashAlgoFlags hashAlgo);

  private:
    WrapperConfig config;
    PredefinedResponses predefinedResponses;

    //spdmcpp::LogClass::Level verbose = spdmcpp::LogClass::Level::Emergency;
};

} // namespace spdm_wrapper
