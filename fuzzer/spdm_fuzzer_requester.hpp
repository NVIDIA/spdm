#include <spdmcpp/common.hpp>
#include <spdmcpp/connection.hpp>

#include "spdm_fuzzer_config.hpp"

using namespace spdmcpp;

namespace spdm_wrapper
{
class Requester
{
  public:
    Requester(IOClass &io, ConnectionClass &connection): io(io), connection(connection) {}

    RetStat startRefreshFlow();
    RetStat handleRecv();
    inline RequestResponseEnum getExpectedResponse() { return connection.getWaitingForResponse();}

  private:
    IOClass         &io;
    ConnectionClass &connection;
};
} //spdm_wrapper
