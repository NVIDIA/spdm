#pragma once

#include <spdmcpp/packet.hpp>

namespace spdmt {
    std::string verToString(const spdmcpp::PacketVersionNumber& ver);
    std::string verToString(spdmcpp::MessageVersionEnum ver);
    std::vector<std::string> capFlagsToStr(spdmcpp::ResponderCapabilitiesFlags flags);
    std::string hashAlgoToStr(spdmcpp::BaseHashAlgoFlags flags);
    std::string asymAlgoToStr(spdmcpp::BaseAsymAlgoFlags flags);
}