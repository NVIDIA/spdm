#pragma once

#include <limits>
#include <string>
#include <iostream>
class WrapperConfig
{
  public:
    /**
     * @brief Thresholds with minimal values required to fuse given messages.
     *        In order to disable use value 256.
     */
    enum class Source {
        Generator,
        RandomStream,
        File
    } source { Source::RandomStream };

    class Threshold {
      public:
        bool enabled;
        uint8_t value;

        bool operator<=(uint8_t rho) const {
            if (!enabled)
                return false;
            return (bool) (value <= rho);
        }
    };

    //WrapperConfig() {
        //reader = [] (char &value) -> bool {
        //    return (bool) std::cin.get(value);
        //};
    //}

    struct {
        Threshold version       { false, 0 };
        Threshold capability    { false, 0 };
        Threshold algorithms    { false, 0 };
        Threshold digests       { false, 0 };
        Threshold certificate   { false, 0 };
        Threshold challengeAuth { false, 0 };
        Threshold measurements  { false, 0 };
    } fuseThrRespMessages;

    struct {
        Threshold nonce                 { false, 0 };
        Threshold hashChain             { false, 0 };
        Threshold hashChainLen          { false, 0 };
        Threshold hashChainVal          { false, 0 };
        Threshold measurementSummary    { false, 0 };
        Threshold measurementSummaryLen { false, 0 };
        Threshold measurementSummaryVal { false, 0 };
        Threshold opaque                { false, 0 };
        Threshold opaqueLen             { false, 0 };
        Threshold opaqueVal             { false, 0 };
        Threshold signature             { false, 0 };
        Threshold signatureLen          { false, 0 };
        Threshold signatureVal          { false, 0 };
    } fuseRespChallengeAuthentication;
    struct {
        Threshold nonce               { false, 0 };
        Threshold measurementBlock    { false, 0 };
        Threshold measurementBlockLen { false, 0 };
        Threshold measurementBlockVal { false, 0 };
        Threshold opaqueData          { false, 0 };
        Threshold opaqueDataLen       { false, 0 };
        Threshold opaqueDataVal       { false, 0 };
        Threshold signature           { false, 0 };
        Threshold signatureLen        { false, 0 };
        Threshold signatureVal        { false, 0 };
    } fuseRespMearurement;

    bool exitAfterFirstFuzzing{false};
    bool enableLogTrace{false};
    int maxIter{13};//{std::numeric_limits<int>::max()};

    struct {
        Threshold all         { false, 0 };
        Threshold version     { false, 0 };
        Threshold messageType { false, 0 };
        Threshold param       { false, 0 };
    } alterHeaderThr;

    Threshold alterDataThr    { false, 0 };

    std::string instructionFilename;

    static Threshold proc2thr(double proc);
    static double thr2proc(Threshold thr);

    typedef bool(*CustomReader)(char &);

    //void readerAddSource(std::istream &stream)
    //{
        //this->stream = stream;
        //reader = [&] (char &value) -> bool {
        //    return (bool) this->stream.get(value);
        //};
    //}
    //CustomReader getReader() const { return reader; }

  private:
    //std::istream stream;
    //WrapperConfig::CustomReader reader;
};

std::ostream & operator<<(std::ostream &out, const WrapperConfig::Threshold &thr);

std::ostream & operator<<(std::ostream &out, const WrapperConfig &config);
