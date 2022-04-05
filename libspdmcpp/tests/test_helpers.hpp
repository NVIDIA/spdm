
#include <spdmcpp/helpers.hpp>
#include <spdmcpp/mbedtls_support.hpp>

#include <fstream>
#include <iostream>


constexpr std::mt19937::result_type mt19937DefaultSeed = 13;

inline void
    fillPseudoRandom(std::span<uint8_t, std::dynamic_extent> buf,
                     std::mt19937::result_type seed = mt19937DefaultSeed)
{
    std::mt19937 gen(seed);
    std::uniform_int_distribution<uint8_t> distrib(1);
    for (auto& b : buf)
    {
        b = distrib(gen);
    }
}

template <typename T>
inline void
    fillPseudoRandomType(T& dst,
                         std::mt19937::result_type seed = mt19937DefaultSeed)
{
    fillPseudoRandom(std::span(reinterpret_cast<uint8_t*>(&dst), sizeof(dst)),
                     seed);
}

template <typename T>
inline T
    returnPseudoRandomType(std::mt19937::result_type seed = mt19937DefaultSeed)
{
    T dst{};
    fillPseudoRandomType(dst, seed);
    return dst;
}

inline void loadFile(std::vector<uint8_t>& buf, const std::string& str)
{
    std::ifstream file;
    buf.clear();
    file.open(str, std::ios::in | std::ios::ate | std::ios::binary);

    buf.resize(file.tellg());
    file.seekg(0, std::ios::beg);

    file.read(reinterpret_cast<char*>(buf.data()), buf.size());
    file.close();
}

inline void appendFile(std::vector<uint8_t>& buf, const std::string& str)
{
    std::ifstream file;
    file.open(str, std::ios::in | std::ios::ate | std::ios::binary);

    size_t off = buf.size();
    size_t fileSize = file.tellg();
    buf.resize(off + fileSize);
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(&buf[off]), fileSize);
    file.close();
}

