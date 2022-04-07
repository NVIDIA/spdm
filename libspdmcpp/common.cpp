
#include <spdmcpp/common.hpp>
#include <spdmcpp/context.hpp>

#include <algorithm>
#include <fstream>

namespace spdmcpp
{

ContextClass::ContextClass()
{
    SupportedVersions.push_back(MessageVersionEnum::SPDM_1_0);
    SupportedVersions.push_back(MessageVersionEnum::SPDM_1_1);
    std::sort(SupportedVersions.begin(), SupportedVersions.end(),
              std::greater());
}
} // namespace spdmcpp
