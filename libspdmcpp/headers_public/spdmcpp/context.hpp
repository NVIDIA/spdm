
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

class ContextClass
{
  public:
    ContextClass()
    {
        SupportedVersions.push_back(MessageVersionEnum::SPDM_1_0);
        SupportedVersions.push_back(MessageVersionEnum::SPDM_1_1);
        std::sort(SupportedVersions.begin(), SupportedVersions.end(),
                  std::greater());
    }

    void registerIo(IOClass& io)
    {
        SPDMCPP_ASSERT(!IO);
        IO = &io;
    }
    void unregisterIo(IOClass& io)
    {
        SPDMCPP_ASSERT(IO == &io);
        IO = nullptr;
    }

    const std::vector<MessageVersionEnum>& getSupportedVersions() const
    {
        return SupportedVersions;
    }

    IOClass& getIO() const
    {
        return *IO;
    }

  protected:
    std::vector<MessageVersionEnum> SupportedVersions;

    IOClass* IO = nullptr;
    uint32_t RetryTimes = 0;
};

} // namespace spdmcpp
