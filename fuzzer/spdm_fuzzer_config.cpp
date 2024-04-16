/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */






#include <iostream>
#include <iomanip>

#include "spdm_fuzzer_config.hpp"

WrapperConfig::Threshold WrapperConfig::proc2thr(double proc)
{
    WrapperConfig::Threshold result { true, 0 };
    if (proc >=100)
    {
        result.value = 0;
    }
    else if (proc <= 0)
    {
        result.enabled = false;
    }
    else
    {
        result.value = (uint8_t) ((double)(std::numeric_limits<uint8_t>::max()) * (1.0 - proc/100.0));
    }
    return result;
}

double WrapperConfig::thr2proc(WrapperConfig::Threshold thr)
{
    double result = 0;
    if (thr.enabled)
    {
        result = 100.0 * (double)(std::numeric_limits<uint8_t>::max() - thr.value) /
            (double) std::numeric_limits<uint8_t>::max();
    }
    return result;
}

std::ostream & operator<<(std::ostream &out, const WrapperConfig::Threshold &thr)
{
    if (thr.enabled)
    {
        out<<WrapperConfig::thr2proc(thr) <<"%";
    }
    else
    {
        out <<"disabled";
    }
    return out;
}

std::ostream& operator<<(std::ostream &out, const WrapperConfig &config)
{
    if (config.exitAfterFirstFuzzing)
    {
        out << "Wrapper exits after first fuzzed message" << std::endl;
    }
    out << "Input data source (Scenario): " << (int) config.source << std::endl;

    out << "Fuzzing messages:" << std::endl;
    if (config.fuseThrRespMessages.version.enabled)
    {
        out << "\tVersion response     "
            << WrapperConfig::thr2proc(config.fuseThrRespMessages.version)
            << "%" << std::endl;
    }
    if (config.fuseThrRespMessages.capability.enabled)
    {
        out << "\tCapability response  "
            << WrapperConfig::thr2proc(config.fuseThrRespMessages.capability)
            << "%" << std::endl;
    }
    if (config.fuseThrRespMessages.algorithms.enabled)
    {
        out << "\tAlgorithms response  "
            << WrapperConfig::thr2proc(config.fuseThrRespMessages.algorithms)
            << "%" << std::endl;
    }
    if (config.fuseThrRespMessages.digests.enabled)
    {
        out << "\tDigest response      "
            << WrapperConfig::thr2proc(config.fuseThrRespMessages.digests)
            << "%" << std::endl;
    }
    if (config.fuseThrRespMessages.certificate.enabled)
    {
        out << "\tCertificate response "
            << WrapperConfig::thr2proc(config.fuseThrRespMessages.certificate)
            << "%" << std::endl;
    }
    if (config.fuseThrRespMessages.challengeAuth.enabled)
    {
        out << "\tChallenge auth. resp "
            << WrapperConfig::thr2proc(config.fuseThrRespMessages.challengeAuth)
            << "%" << std::endl;
    }
    if (config.fuseThrRespMessages.measurements.enabled)
    {
        out << "\tMeasurements resp.   "
            << WrapperConfig::thr2proc(config.fuseThrRespMessages.measurements)
            << "%" << std::endl;
    }

    out << "Altering header probability:            " << WrapperConfig::thr2proc(config.alterHeaderThr.all) << "%" << std::endl;
    //out<<std::setprecision(0);
    if (config.source == WrapperConfig::Source::Generator)
    {
        out << "\tVersion alter probability:      " << WrapperConfig::thr2proc(config.alterHeaderThr.version)     << "%" << std::endl;
        out << "\tMessage Type alter probability: " << WrapperConfig::thr2proc(config.alterHeaderThr.messageType) << "%" << std::endl;
        out << "\tParam 1/2 alter probability:    " << WrapperConfig::thr2proc(config.alterHeaderThr.param)       << "%" << std::endl;
    }
    out << "Altering payloads' data probability:    " << WrapperConfig::thr2proc(config.alterDataThr)           << "%" << std::endl;

    return out;
}
