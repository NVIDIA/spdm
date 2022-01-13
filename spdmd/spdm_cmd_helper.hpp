#pragma once

#include <err.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <CLI/CLI.hpp>

#include <cstring>
#include <iomanip>
#include <iostream>
#include <utility>

namespace sldmd
{

namespace helper
{

/** @brief print the debug messages if pldmverbose is > 0
 *
 *  @param[in]  spdmVerbose - verbosity flag - 0..3
 *
 *  @return - None
 */

template <class T>
void Logger(int pldmverbose, const char* msg, const T& data)
{
    if (pldmverbose>0)
    {
        std::stringstream s;
        s << data;
        std::cout << msg << s.str() << std::endl;
    }
}

class CommandInterface
{

  public:
    explicit CommandInterface(const char* type, const char* name,
                              CLI::App* app) :
        pldmType(type),
        commandName(name), mctp_eid(PLDM_ENTITY_ID), pldmVerbose(false),
        instanceId(0)
    {
        app->add_flag("-v, --verbose", pldmVerbose);
    }

    virtual ~CommandInterface() = default;

    virtual std::pair<int, std::vector<uint8_t>> createRequestMsg() = 0;

    virtual void parseResponseMsg(struct pldm_msg* responsePtr,
                                  size_t payloadLength) = 0;

    virtual void exec();

    int pldmSendRecv(std::vector<uint8_t>& requestMsg,
                     std::vector<uint8_t>& responseMsg);

  private:
    const std::string commandName;
    int pldmVerbose;

  protected:
    uint8_t instanceId;
};

} // namespace helper
} // namespace spdmd
