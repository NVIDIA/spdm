#pragma once

#include <bitset>

namespace spdm
{

constexpr size_t maxInstanceIds = 32;

/** @class InstanceId
 *  @brief Implementation of SPDM instance id
 */
class InstanceId
{
  public:
    /** @brief Get next unused instance id
     *  @return - SPDM instance id
     */
    uint8_t next();

    /** @brief Mark an instance id as unused
     *  @param[in] instanceId - SPDM instance id to be freed
     */
    void markFree(uint8_t instanceId)
    {
        id.set(instanceId, false);
    }

  private:
    std::bitset<maxInstanceIds> id;
};

} // namespace spdm
