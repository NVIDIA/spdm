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
#include <iostream>
#include <fstream>
#include <string>
#include <memory>

#include <CLI/CLI.hpp>

#include "spdm_fuzzer_app.hpp"
#include "spdm_fuzzer_requester.hpp"
#include "spdm_fuzzer_responder.hpp"
#include "spdmcpp/enum_defs.hpp"

#include "config.h"
#include "spdm_fuzzer_app.hpp"
#include "spdm_fuzzer_version.hpp"
#include "spdm_fuzzer_config.hpp"

using namespace std;

int main(int argc, char** argv)
{
    int returnCode = 0;

    try
    {
        spdm_wrapper::SpdmWrapperApp app;
        app.setupCli(argc, argv);

        bool result = app.run(BaseAsymAlgoFlags::TPM_ALG_ECDSA_ECC_NIST_P521,
            BaseHashAlgoFlags::TPM_ALG_SHA_512);
        if (result)
            std::cout<<"All OK"<<std::endl;
        else
            std::cout<<"Flow failed"<<std::endl;
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "exception reached main '" << e.what() << std::endl;
        abort();
    }

    return returnCode;
}

namespace spdm_wrapper
{

bool SpdmWrapperApp::run(BaseAsymAlgoFlags asymAlgo, BaseHashAlgoFlags hashAlgo)
{
    bool result = false;
    LogClass log(std::cout);
    log.setLogLevel(spdmcpp::LogClass::Level::Debug);
    ContextClass context;

    std::list<std::vector<uint8_t>> queue1;
    std::list<std::vector<uint8_t>> queue2;
    FixtureIOClass ioResponder(config.enableLogTrace?"commlog_responder.txt":"", queue1, queue2);
    auto ioRequester = std::make_shared<FixtureIOClass>(config.enableLogTrace?"commlog_requester.txt":"", queue2, queue1);
    static constexpr auto eid = 14;
    static constexpr auto transport = "PCIe";
    FixtureTransportClass trans(eid);            //Option add eid to config
    ConnectionClass Connection(context, log, eid, "PCIe");

    context.registerIo(ioRequester, transport);
    Connection.registerTransport(trans);

    Requester requester(*ioRequester, Connection);

    std::ifstream fileStr;
    if (!config.instructionFilename.empty())
        fileStr.open(config.instructionFilename, std::ifstream::in);

    std::istream &str = config.instructionFilename.empty() ? std::cin : fileStr;
    FuzzingResponder responder(ioResponder, trans, config, predefinedResponses, asymAlgo, hashAlgo, str);

    bool doReset = true;
    bool modified = false;

    int iter = 1;
    for (; ;)
    {
    //  Requester sends message
        if (doReset)
        {
            std::cout<<"########### Requester Reset" << std::endl;
            ioResponder.clearTx();
            ioRequester->clearTx();

            responder.resetState();
            requester.startRefreshFlow();   // Start new session
            doReset = false;
        }
        else
        {
            std::cout<<"########### Requester handleRecv()" << std::endl;
            auto rs = requester.handleRecv();
            if (rs == RetStat::OK && requester.getExpectedResponse() == RequestResponseEnum::INVALID)
            {
                result = true;
                break;
                //All OK End.
            }
            if (rs != RetStat::OK)
                doReset = true;
            if (config.exitAfterFirstFuzzing)
                break;
        }
        if (doReset)
            continue;

    //  Responder sends message
        std::cout<<"########### Response no " << iter << " ("
            << requester.getExpectedResponse() << ")";
        std::cout << std::endl;
        responder.sendResponse(requester.getExpectedResponse(), modified);

    //  Taking decision about next iteration
        if (++iter > config.maxIter)
            break;
    }
    Connection.unregisterTransport(trans);
    context.unregisterIo(transport);

    return result;
}


void SpdmWrapperApp::setupCli(int argc, char** argv)
{
    CLI::App app{spdm_wrapper::description::name + ", version " +
                 spdm_wrapper::description::version};

    bool useGrammar;
    app.add_flag("-e, --exitAfterFirstFuzzing", config.exitAfterFirstFuzzing, "Exit after first fuzzing");
    app.add_flag("-g, --grammar",               useGrammar,                   "Use grammar in fuzz generator");
    app.add_flag("--enableLogTrace",            config.enableLogTrace,        "Log communication to files");

    struct {
        double all           {0};
        double version       {0};
        double capability    {0};
        double algorithms    {0};
        double digests       {0};
        double certificate   {0};
        double challengeAuth {0};
        double measurements  {0};
    } doFuseResponseMessages;

    app.add_option("--fResponsesAll",     doFuseResponseMessages.all,
        "Default probability of altering all response messages (0-100). Value can be overriden.")
        ->check(CLI::Range(0.0, 100.0));

    app.add_option("--fRespVersion",      doFuseResponseMessages.version,
        "Prob. of altering resp. msg. Version (0-100)")
        ->check(CLI::Range(0.0, 100.0));

    app.add_option("--fRespCapabilities", doFuseResponseMessages.capability,
        "Prob. of altering resp. msg. Capability (0-100)")
        ->check(CLI::Range(0.0, 100.0));

    app.add_option("--fRespAlgorithms",   doFuseResponseMessages.algorithms,
        "Prob. of altering resp. msg. Algorithms (0-100)")
        ->check(CLI::Range(0.0, 100.0));

    app.add_option("--fRespDigest",       doFuseResponseMessages.digests,
        "Prob. of altering resp. msg. Digest (0-100)")
        ->check(CLI::Range(0.0, 100.0));

    app.add_option("--fRespCertificate",  doFuseResponseMessages.certificate,
        "Prob. of altering resp. msg. Certificate (0-100)")
        ->check(CLI::Range(0.0, 100.0));


    struct {
        double nonce                 { 0 };
        double hashChain             { 0 };
        double hashChainLen          { 0 };
        double hashChainVal          { 0 };
        double measurementSummary    { 0 };
        double measurementSummaryLen { 0 };
        double measurementSummaryVal { 0 };
        double opaque                { 0 };
        double opaqueLen             { 0 };
        double opaqueVal             { 0 };
        double signature             { 0 };
        double signatureLen          { 0 };
        double signatureVal          { 0 };
    } fuseRespChallengeAuthentication;

    app.add_option("--fRespChallengeAuth",doFuseResponseMessages.challengeAuth,
        "Prob. of altering resp. msg. Challenge Authentication (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespChallengeAuthNonce",fuseRespChallengeAuthentication.nonce,
        "Prob. of altering resp. msg. Challenge Authentication Nonce data (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespChallengeAuthHashChain",fuseRespChallengeAuthentication.hashChain,
        "Prob. of altering resp. msg. Challenge Authentication Hash chain (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespChallengeAuthHashChainLen",fuseRespChallengeAuthentication.hashChainLen,
        "Prob. of altering resp. msg. Challenge Authentication: Length of hash chain (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespChallengeAuthHashChainVal",fuseRespChallengeAuthentication.hashChainVal,
        "Prob. of altering resp. msg. Challenge Authentication: Single item of hash chain (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespChallengeAuthMeasurementSummary",fuseRespChallengeAuthentication.measurementSummary,
        "Prob. of altering resp. msg. Challenge Authentication: Measurement summary (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespChallengeAuthMeasurementSummaryLen",fuseRespChallengeAuthentication.measurementSummaryLen,
        "Prob. of altering resp. msg. Challenge Authentication: length of measurement summary (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespChallengeAuthMeasurementSummaryVal",fuseRespChallengeAuthentication.measurementSummaryVal,
        "Prob. of altering resp. msg. Challenge Authentication: single item of measurement summary (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespChallengeAuthOpaque",fuseRespChallengeAuthentication.opaque,
        "Prob. of altering resp. msg. Challenge Authentication: Opaque (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespChallengeAuthOpaqueLen",fuseRespChallengeAuthentication.opaqueLen,
        "Prob. of altering resp. msg. Challenge Authentication: length of opaque data (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespChallengeAuthOpaqueVal",fuseRespChallengeAuthentication.opaqueVal,
        "Prob. of altering resp. msg. Challenge Authentication: single item of opaque data (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespChallengeAuthSignature",fuseRespChallengeAuthentication.signature,
        "Prob. of altering resp. msg. Challenge Authentication: Signature (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespChallengeAuthSignatureLen",fuseRespChallengeAuthentication.signatureLen,
        "Prob. of altering resp. msg. Challenge Authentication: length of signature (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespChallengeAuthSignatureVal",fuseRespChallengeAuthentication.signatureVal,
        "Prob. of altering resp. msg. Challenge Authentication: single item of signature (0-100)")
        ->check(CLI::Range(0.0, 100.0));

    struct {
        double nonce               { 0 };
        double measurementBlock    { 0 };
        double measurementBlockLen { 0 };
        double measurementBlockVal { 0 };
        double opaqueData          { 0 };
        double opaqueDataLen       { 0 };
        double opaqueDataVal       { 0 };
        double signature           { 0 };
        double signatureLen        { 0 };
        double signatureVal        { 0 };
    } respMearurement;
    app.add_option("--fRespMeasurements", doFuseResponseMessages.measurements,
        "Prob. of altering resp. msg. Measurements (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespMeasurementsNonce", respMearurement.nonce,
        "Prob. of altering resp. msg. Measurements Nonce vector (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespMeasurementsBlock", respMearurement.measurementBlock,
        "Prob. of altering resp. msg. Measurements Block with data (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespMeasurementsBlockLen", respMearurement.measurementBlockLen,
        "Prob. of altering resp. msg. Measurements Length of Block with data (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespMeasurementsBlockVal", respMearurement.measurementBlockVal,
        "Prob. of altering resp. msg. Measurements Single byte of block with data (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespMeasurementsOpaque", respMearurement.opaqueData,
        "Prob. of altering resp. msg. Measurements Opaque (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespMeasurementsOpaqueLen", respMearurement.opaqueDataLen,
        "Prob. of altering resp. msg. Measurements Length of Opaque with data (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespMeasurementsOpaqueVal", respMearurement.opaqueDataVal,
        "Prob. of altering resp. msg. Measurements Single byte of opaque data (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespMeasurementsSignature", respMearurement.signature,
        "Prob. of altering resp. msg. Signature (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespMeasurementsSignatureLen", respMearurement.signatureLen,
        "Prob. of altering resp. msg. Measurements signature's length (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--fRespMeasurementsSignatureVal", respMearurement.signatureVal,
        "Prob. of altering resp. msg. Measurements single byte of signature data (0-100)")
        ->check(CLI::Range(0.0, 100.0));

    struct {
        double all         {30};
        double version     {10};
        double messageType {10};
        double param       {10};
    } alterHeaderProb;

    app.add_option("--alterHeader",        alterHeaderProb.all,         "Probability of altering header (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--alterHeaderVersion", alterHeaderProb.version,     "Probability of altering version in header (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--alterHeaderType",    alterHeaderProb.messageType, "Probability of altering message type in header (0-100)")
        ->check(CLI::Range(0.0, 100.0));
    app.add_option("--alterHeaderParam",   alterHeaderProb.param,       "Probability of altering param1 or param2 in header (0-100)")
        ->check(CLI::Range(0.0, 100.0));

    double alterDataProb;
    app.add_option("--alterPayloadData",   alterDataProb,               "Probability of altering payloads' data (0-100)")
        ->check(CLI::Range(0.0, 100.0));


    std::string logFilePath;
    app.add_option("--readLogFile",   logFilePath,               "Read log file with responses in order to reuse those responses");

    std::string responsesFilePath;
    app.add_option("--readResponseFile",   responsesFilePath,    "Read file with responses (in hex format) in order to reuse those responses");

    app.add_option("--maxMsgExchange", config.maxIter,           "Maximum number of messages sent by mocked responder") -> check(CLI::Range(0, 100));

    app.add_option("-f, --instructionFile", config.instructionFilename, "file with instruction that replaces input stream");

    try
    {
        (app).parse((argc), (argv));
    }
    catch (const CLI::ParseError& e)
    {
        exit((app).exit(e));
    }

    if (!config.instructionFilename.empty())
    {
        std::cout<<"Fuzzer reads instructions from file: " << config.instructionFilename << std::endl;
    }

    if (!responsesFilePath.empty())
    {
        predefinedResponses.readFromHexFile(responsesFilePath);
        config.source = WrapperConfig::Source::File;
    }
    else if (!logFilePath.empty())
    {
        predefinedResponses.readFromLogFile(logFilePath);
        config.source = WrapperConfig::Source::File;
    }
    else
    {
        config.source = (useGrammar) ?
            WrapperConfig::Source::Generator :
            WrapperConfig::Source::RandomStream;
    }

    if (config.source == WrapperConfig::Source::File)
    {
        std::cout << "Predefined messages (" << predefinedResponses.getAllResponses().size() << ")" << std::endl;
        for (auto& [key, value] : predefinedResponses.getAllResponses())
        {
            std::cout<<"Type: " << std::hex << int(key) << std::dec << " Value vec len: " << value.size() << std::endl;
        }
    }

    if (doFuseResponseMessages.all > 0)
    {
        config.fuseThrRespMessages.version       = WrapperConfig::proc2thr(doFuseResponseMessages.all);
        config.fuseThrRespMessages.capability    = WrapperConfig::proc2thr(doFuseResponseMessages.all);
        config.fuseThrRespMessages.algorithms    = WrapperConfig::proc2thr(doFuseResponseMessages.all);
        config.fuseThrRespMessages.digests       = WrapperConfig::proc2thr(doFuseResponseMessages.all);
        config.fuseThrRespMessages.certificate   = WrapperConfig::proc2thr(doFuseResponseMessages.all);
        config.fuseThrRespMessages.challengeAuth = WrapperConfig::proc2thr(doFuseResponseMessages.all);
        config.fuseThrRespMessages.measurements  = WrapperConfig::proc2thr(doFuseResponseMessages.all);
    }

    std::cout << "doFuseResponseMessages.all        = " << doFuseResponseMessages.all << std::endl;
    std::cout << "doFuseResponseMessages.version    = " << doFuseResponseMessages.version << std::endl;
    std::cout << "doFuseResponseMessages.algorithms = " << doFuseResponseMessages.algorithms << std::endl;

    if (doFuseResponseMessages.version > 0)
        config.fuseThrRespMessages.version       = WrapperConfig::proc2thr(doFuseResponseMessages.version);

    if (doFuseResponseMessages.capability > 0)
        config.fuseThrRespMessages.capability    = WrapperConfig::proc2thr(doFuseResponseMessages.capability);

    if (doFuseResponseMessages.algorithms > 0)
        config.fuseThrRespMessages.algorithms    = WrapperConfig::proc2thr(doFuseResponseMessages.algorithms);

    if (doFuseResponseMessages.digests > 0)
        config.fuseThrRespMessages.digests       = WrapperConfig::proc2thr(doFuseResponseMessages.digests);

    if (doFuseResponseMessages.certificate > 0)
        config.fuseThrRespMessages.certificate   = WrapperConfig::proc2thr(doFuseResponseMessages.certificate);

// Options for fuzzing response challenge authentication message
    if (doFuseResponseMessages.challengeAuth > 0)
        config.fuseThrRespMessages.challengeAuth = WrapperConfig::proc2thr(doFuseResponseMessages.challengeAuth);
    if (fuseRespChallengeAuthentication.nonce > 0)
        config.fuseRespChallengeAuthentication.nonce  = WrapperConfig::proc2thr(fuseRespChallengeAuthentication.nonce);
    if (fuseRespChallengeAuthentication.hashChain > 0)
        config.fuseRespChallengeAuthentication.hashChain  = WrapperConfig::proc2thr(fuseRespChallengeAuthentication.hashChain);
    if (fuseRespChallengeAuthentication.hashChainLen > 0)
        config.fuseRespChallengeAuthentication.hashChainLen  = WrapperConfig::proc2thr(fuseRespChallengeAuthentication.hashChainLen);
    if (fuseRespChallengeAuthentication.hashChainVal > 0)
        config.fuseRespChallengeAuthentication.hashChainVal  = WrapperConfig::proc2thr(fuseRespChallengeAuthentication.hashChainVal);
    if (fuseRespChallengeAuthentication.measurementSummary > 0)
        config.fuseRespChallengeAuthentication.measurementSummary  = WrapperConfig::proc2thr(fuseRespChallengeAuthentication.measurementSummary);
    if (fuseRespChallengeAuthentication.measurementSummaryLen > 0)
        config.fuseRespChallengeAuthentication.measurementSummaryLen  = WrapperConfig::proc2thr(fuseRespChallengeAuthentication.measurementSummaryLen);
    if (fuseRespChallengeAuthentication.measurementSummaryVal > 0)
        config.fuseRespChallengeAuthentication.measurementSummaryVal  = WrapperConfig::proc2thr(fuseRespChallengeAuthentication.measurementSummaryVal);
    if (fuseRespChallengeAuthentication.opaque > 0)
        config.fuseRespChallengeAuthentication.opaque  = WrapperConfig::proc2thr(fuseRespChallengeAuthentication.opaque);
    if (fuseRespChallengeAuthentication.opaqueLen > 0)
        config.fuseRespChallengeAuthentication.opaqueLen  = WrapperConfig::proc2thr(fuseRespChallengeAuthentication.opaqueLen);
    if (fuseRespChallengeAuthentication.opaqueVal > 0)
        config.fuseRespChallengeAuthentication.opaqueVal  = WrapperConfig::proc2thr(fuseRespChallengeAuthentication.opaqueVal);
    if (fuseRespChallengeAuthentication.signature > 0)
        config.fuseRespChallengeAuthentication.signature  = WrapperConfig::proc2thr(fuseRespChallengeAuthentication.signature);
    if (fuseRespChallengeAuthentication.signatureLen > 0)
        config.fuseRespChallengeAuthentication.signatureLen  = WrapperConfig::proc2thr(fuseRespChallengeAuthentication.signatureLen);
    if (fuseRespChallengeAuthentication.signatureVal > 0)
        config.fuseRespChallengeAuthentication.signatureVal  = WrapperConfig::proc2thr(fuseRespChallengeAuthentication.signatureVal);

// Options for fuzzing response measurements message
    if (doFuseResponseMessages.measurements > 0)
        config.fuseThrRespMessages.measurements  = WrapperConfig::proc2thr(doFuseResponseMessages.measurements);
    if (respMearurement.nonce > 0)
        config.fuseRespMearurement.nonce  = WrapperConfig::proc2thr(respMearurement.nonce);
    if (respMearurement.measurementBlock > 0)
        config.fuseRespMearurement.measurementBlock  = WrapperConfig::proc2thr(respMearurement.measurementBlock);
    if (respMearurement.measurementBlockLen > 0)
        config.fuseRespMearurement.measurementBlockLen  = WrapperConfig::proc2thr(respMearurement.measurementBlockLen);
    if (respMearurement.measurementBlockVal > 0)
        config.fuseRespMearurement.measurementBlockVal  = WrapperConfig::proc2thr(respMearurement.measurementBlockVal);
    if (respMearurement.opaqueData > 0)
        config.fuseRespMearurement.opaqueData  = WrapperConfig::proc2thr(respMearurement.opaqueData);
    if (respMearurement.opaqueDataLen > 0)
        config.fuseRespMearurement.opaqueDataLen  = WrapperConfig::proc2thr(respMearurement.opaqueDataLen);
    if (respMearurement.opaqueDataVal > 0)
        config.fuseRespMearurement.opaqueDataVal  = WrapperConfig::proc2thr(respMearurement.opaqueDataVal);
    if (respMearurement.signature > 0)
        config.fuseRespMearurement.signature  = WrapperConfig::proc2thr(respMearurement.signature);
    if (respMearurement.signatureLen > 0)
        config.fuseRespMearurement.signatureLen  = WrapperConfig::proc2thr(respMearurement.signatureLen);
    if (respMearurement.signatureVal > 0)
        config.fuseRespMearurement.signatureVal  = WrapperConfig::proc2thr(respMearurement.signatureVal);

    config.alterHeaderThr.all                = WrapperConfig::proc2thr(alterHeaderProb.all);
    config.alterHeaderThr.version            = WrapperConfig::proc2thr(alterHeaderProb.version);
    config.alterHeaderThr.messageType        = WrapperConfig::proc2thr(alterHeaderProb.messageType);
    config.alterHeaderThr.param              = WrapperConfig::proc2thr(alterHeaderProb.param);
    config.alterDataThr                      = WrapperConfig::proc2thr(alterDataProb);
    cout << "Current config:" << std::endl;
    cout << config << std::endl;

    cout << "config.fuseThrRespMessages.version = " << config.fuseThrRespMessages.version << std::endl;
}

} // namespace spdm_wrapper
