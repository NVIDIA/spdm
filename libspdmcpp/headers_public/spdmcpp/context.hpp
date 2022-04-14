
#pragma once

#include "assert.hpp"
#include "common.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>
#include <vector>

namespace spdmcpp
{
// TODO implement warnings and global (maybe granular?) warning policies!?
//  and/or error policies as well, although those would have to be much more
//  specific I imagine...

class ContextClass
{
    friend ConnectionClass; // TODO remove!!!
  public:
    ContextClass()
    {
        SupportedVersions.push_back(MessageVersionEnum::SPDM_1_0);
        SupportedVersions.push_back(MessageVersionEnum::SPDM_1_1);
        std::sort(SupportedVersions.begin(), SupportedVersions.end(),
                  std::greater());
    }

    void registerIo(IOClass* io)
    {
        SPDMCPP_ASSERT(!IO);
        IO = io;
    }
    void unregisterIo(IOClass* io)
    {
        SPDMCPP_ASSERT(IO == io);
        IO = nullptr;
    }

    const std::vector<MessageVersionEnum>& getSupportedVersions() const
    {
        return SupportedVersions;
    }

  protected:
    std::vector<MessageVersionEnum> SupportedVersions;

    IOClass* IO = nullptr;
    uint32_t RetryTimes = 0;
};
} // namespace spdmcpp
