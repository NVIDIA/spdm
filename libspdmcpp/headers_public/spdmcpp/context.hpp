
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

/** @class ContextClass
 *  @brief Class for storing common configuration and interface for multiple
 * ConnectionClasses
 */
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

    /** @brief Registers an IOClass for handling the communication channel
     * (typically socket)
     *  @param[in] io - Object to be used for sending/reading messages,
     * ContextClass does not take ownership and will not deallocate the
     * object
     */
    void registerIo(IOClass& io)
    {
        SPDMCPP_ASSERT(!IO);
        IO = &io;
    }

    /** @brief Unregisters the IOClass object, should be called before
     * destroying io
     *  @param[in] transport - the parameter is provided just for verifying
     * correctness (register and unregister calls must match and can't be
     * redundant)
     */
    void unregisterIo(IOClass& io)
    {
        SPDMCPP_ASSERT(IO == &io);
        IO = nullptr;
    }

    /** @brief SPDM versions that we're configured to support
     */
    const std::vector<MessageVersionEnum>& getSupportedVersions() const
    {
        return SupportedVersions;
    }

    IOClass& getIO() const
    {
        return *IO;
    }

  protected:
    /** @brief SPDM versions that we're configured to support
     */
    std::vector<MessageVersionEnum> SupportedVersions;

    IOClass* IO = nullptr;
};

} // namespace spdmcpp
