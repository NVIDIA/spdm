#pragma once

#include <stdint.h>
#include <string>
#include <regex>
#include <vector>
#include <map>
#include <filesystem>

namespace fs = std::filesystem;

class PredefinedResponses
{
public:
    PredefinedResponses() {};

    bool readFromHexFile(fs::path path);
    bool readFromLogFile(fs::path path);

    const std::vector<uint8_t>& getResponse(uint8_t msgType, int index = 0) const;

    bool containsData() const { return responses.size() > 0; }
    const std::multimap<uint8_t, std::vector<uint8_t>>& getAllResponses() const { return responses; }

private:
    std::vector<uint8_t> readMsgRaw(const std::string &msgStr, size_t pos = 0);

    std::multimap<uint8_t, std::vector<uint8_t>> responses;
    std::vector<uint8_t> empty;
};