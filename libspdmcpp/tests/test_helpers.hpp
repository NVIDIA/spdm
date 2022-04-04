
#include <spdmcpp/helpers.hpp>
#include <spdmcpp/mbedtls_support.hpp>

#include <fstream>
#include <iostream>


constexpr std::mt19937::result_type mt19937DefaultSeed = 13;

inline void
    fillPseudoRandom(uint8_t* buf, size_t len,
                     std::mt19937::result_type seed = mt19937DefaultSeed)
{
    std::mt19937 gen(seed);
    std::uniform_int_distribution<uint8_t> distrib(1);
    for (size_t i = 0; i < len; ++i)
    {
        buf[i] = distrib(gen);
    }
}

inline void
    fillPseudoRandom(std::vector<uint8_t>& buf,
                     std::mt19937::result_type seed = mt19937DefaultSeed)
{
    fillPseudoRandom(buf.data(), buf.size(), seed);
}

template <size_t N>
void fillPseudoRandom(std::array<uint8_t, N>& buf,
                      std::mt19937::result_type seed = mt19937DefaultSeed)
{
    fillPseudoRandom(buf.data(), buf.size(), seed);
}

template <size_t N>
void fillPseudoRandom(uint8_t (&buf)[N],
                      std::mt19937::result_type seed = mt19937DefaultSeed)
{
    fillPseudoRandom(buf, N, seed);
}

template <typename T>
inline void
    fillPseudoRandomType(T& dst,
                         std::mt19937::result_type seed = mt19937DefaultSeed)
{
    fillPseudoRandom(reinterpret_cast<uint8_t*>(&dst), sizeof(dst), seed);
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
    // file << buf;
    file.close();
}

inline void appendFile(std::vector<uint8_t>& buf, const std::string& str)
{
    std::ifstream file;
    file.open(str, std::ios::in | std::ios::ate | std::ios::binary);

    size_t off = buf.size();
    buf.resize(off + file.tellg());
    file.seekg(0, std::ios::beg);

    file.read(reinterpret_cast<char*>(buf.data() + off), buf.size());
    // file << buf;
    file.close();
}

