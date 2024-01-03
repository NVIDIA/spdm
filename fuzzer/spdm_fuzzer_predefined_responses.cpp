/*
 * Copyright (C) NVIDIA Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string.h>
#include <cassert>
#include <iostream>
#include <fstream>

#include "spdm_fuzzer_predefined_responses.hpp"

constexpr char responseBegin[] = "ResponseBuffer = ";
constexpr size_t responseBeginLen = strlen(responseBegin);

bool PredefinedResponses::readFromHexFile(fs::path path)
{
    std::ifstream responesFile(path);

    std::string line;

    while (std::getline(responesFile, line))
    {
        std::vector<uint8_t> msg = readMsgRaw(line);
        if (msg.size() > 3)
            responses.emplace(3, msg);
    }

    return responses.size() > 0;
}

bool PredefinedResponses::readFromLogFile(fs::path path)
{
    std::ifstream responesFile(path);
    std::string line;

    int noOfReadLines;
    while (std::getline(responesFile, line))
    {
        noOfReadLines++;
        size_t pos;
        if (std::string::npos == (pos = line.find(responseBegin)))
            continue;

        std::cerr<<"Parsing line: " << line << std::endl;

        pos += responseBeginLen;

        std::vector<uint8_t> msg = readMsgRaw(line, pos);

        if (msg.size() > 3)
            responses.emplace(msg[3], msg);
    }
    std::cerr<<"Parsed "<<noOfReadLines<<" lines" << std::endl;
    return responses.size() > 0;
}

const std::vector<uint8_t>& PredefinedResponses::getResponse(uint8_t msgType, int index) const
{
    if (responses.count(msgType) == 0)
    {
//        std::cerr<<"Can't find message type " << (int) msgType << std::endl;
        return empty;
    }

    auto itr1 = responses.lower_bound(msgType);
    auto itr2 = responses.upper_bound(msgType);

    if (itr1 == std::end(responses) && std::distance(itr1, itr2) < index)
        return empty;

    std::advance(itr1, index);
    return itr1->second;
}

std::vector<uint8_t> PredefinedResponses::readMsgRaw(const std::string &msgStr, size_t pos)
{
   std::vector<uint8_t> result;
    size_t x = pos;
    while (pos < msgStr.length())
    {
        try
        {
            int val = std::stoi(msgStr.substr(pos), &x, 16);
            pos+=x;
            result.push_back(val & 0xFF);
        }
        catch(const std::exception& e)
        {
            //What to do with broken data. Skip it or add random.
            x++;
            continue;
        }
    }
    std::cerr<<std::endl;

   return result;
}
