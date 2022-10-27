#include "spdm_fuzzer_fixture.hpp"

namespace spdm_wrapper
{
RetStat FixtureIOClass::write(const std::vector<uint8_t>& buf,
                timeout_us_t /*timeout*/)
{
    writeQueue.push_back(buf);
    if (logStream.is_open())
    {
        logStream << "TX> ";
        logStream << std::hex << std::setfill('0') << std::setw(2);
        for (auto v : buf)
        {
            logStream << int(v) << " ";
        }
        logStream << std::endl;
    }
    return RetStat::OK;
}
RetStat FixtureIOClass::read(std::vector<uint8_t>& buf,
                timeout_us_t /*timeout*/)
{
    if (readQueue.empty())
    {
        return RetStat::ERROR_UNKNOWN;
    }
    std::swap(buf, readQueue.front());

    if (logStream.is_open())
    {
        logStream << "RX> ";
        logStream << std::hex << std::setfill('0') << std::setw(2);
        for (auto v : buf) {
            logStream << int(v) << " ";
        }
        logStream << std::endl;
    }
    readQueue.pop_front();
    return RetStat::OK;
}
}
