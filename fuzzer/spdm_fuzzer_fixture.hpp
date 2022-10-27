#include <list>
#include <vector>

#include <spdmcpp/assert.hpp>
#include <spdmcpp/common.hpp>
#include <spdmcpp/connection.hpp>
#include <spdmcpp/context.hpp>
#include <spdmcpp/mbedtls_support.hpp>
#include <spdmcpp/mctp_support.hpp>

#include <libspdmcpp/headers/spdmcpp/helpers.hpp>
#include <fstream>
#include <string>

using namespace spdmcpp;

namespace spdm_wrapper
{

class FixtureTransportClass : public MctpTransportClass
{
  public:
    FixtureTransportClass() = delete;
    FixtureTransportClass(int eid) : MctpTransportClass(eid) {}

    spdmcpp::RetStat setupTimeout(spdmcpp::timeout_us_t /*timeout*/) override
    {
        return spdmcpp::RetStat::OK;
    }
};

class FixtureIOClass : public spdmcpp::IOClass
{
  public:
    FixtureIOClass() = delete;
    FixtureIOClass(std::string_view logName, std::list<std::vector<uint8_t>> &readQueue, std::list<std::vector<uint8_t>> &writeQueue):
      readQueue(readQueue), writeQueue(writeQueue)
    {
        if (!logName.empty())
        {
            logStream.open(std::string(logName).c_str(), std::ios::app);
        }
    }

    RetStat write(const std::vector<uint8_t>& buf,
                  timeout_us_t /*timeout*/ = timeoutUsInfinite) override;

    RetStat read(std::vector<uint8_t>& buf,
                 timeout_us_t /*timeout*/ = timeoutUsInfinite) override;

    void clearTx() { writeQueue.clear(); }

  private:
    std::list<std::vector<uint8_t>> &readQueue;
    std::list<std::vector<uint8_t>> &writeQueue;
    std::ofstream logStream;
};

}
