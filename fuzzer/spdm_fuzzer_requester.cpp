#include "spdm_fuzzer_requester.hpp"
#include "spdm_fuzzer_responder.hpp"

using namespace spdmcpp;

namespace spdm_wrapper
{
RetStat Requester::startRefreshFlow()
{
    return connection.refreshMeasurements(0);
}

RetStat Requester::handleRecv()
{
    std::vector<uint8_t> buf;
    auto res = io.read(buf);

    if (res != RetStat::OK)
    {
        return res;
    }
    EventReceiveClass ev(buf);
    return  connection.handleEvent(ev);
}
}

