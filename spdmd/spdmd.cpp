/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
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

#include "config.h"

#include "mctp_endpoint_discovery.hpp"
#include "spdmcpp/common.hpp"
#include "spdmd_app.hpp"
#include "spdmd_version.hpp"

#include <bits/stdc++.h>

#include <CLI/CLI.hpp>

#include <string>

using namespace std;
using namespace spdmd;
using namespace sdbusplus;

// Define the SPDM default dbus path location for objects.
constexpr auto spdmRootObjectPath = "/xyz/openbmc_project/SPDM";
constexpr auto spdmDefaultService = "xyz.openbmc_project.SPDM";

namespace spdmd
{

SpdmdApp::SpdmdApp() : SpdmdAppContext(std::cout)
{}

void SpdmdApp::setupCli(int argc, char** argv)
{
    CLI::App app{spdmd::description::name + ", version " +
                 spdmd::description::version};

    CLI::Option* opt =
        app.add_option("-v, --verbose", verbose, "Verbose log level (0-7)");
    opt->check(CLI::Range(0, 7));

    std::vector<std::string> cache;
    opt = app.add_option(
        "--cached_measurements", cache,
        "[all | eid0, eid1,...] Enables automatic getting of measurements for all devices or the listed EIDs upon discovery but no quicker than '--cached_measurements_delay' seconds after launch.");
    opt->delimiter(',');
    opt->check(CLI::IsMember({"all"}) | CLI::Range(1, 254));

    app.add_option(
        "--cached_measurements_delay", measureOnDiscoveryDelay,
        "[seconds]; The initial communication should be performed after running the daemon with a delay configured by this param. Default value: 60.");

    try
    {
        (app).parse((argc), (argv));
    }
    catch (const CLI::ParseError& e)
    {
        exit((app).exit(e));
    }

    if (verbose > spdmcpp::LogClass::Level::Emergency)
    {
        getLog().setLogLevel(verbose);
        getLog().print("Verbose log level set to " +
                       obmcprj::Logging::server::convertForMessage(
                           (obmcprj::Logging::server::Entry::Level)verbose) +
                       "\n");
    }
    else
    {
        getLog().setLogLevel(spdmcpp::LogClass::Level::Error);
    }

    if (!cache.empty())
    {
        measureOnDiscovery = true;
        if (measureOnDiscoveryDelay == std::chrono::seconds(0))
        {
            measureOnDiscoveryActive = true;
            // initial mctp discovery happens early on so if delay is 0 we need
            // to enable this already here
        }
        if (!(cache.size() == 1 && cache[0] == "all"))
        {
            try
            {
                for (auto& i : cache)
                {
                    cachedMeasurements.insert(std::stoi(i));
                }
            }
            catch (const std::invalid_argument& e)
            {
                throw std::invalid_argument(
                    "--cached_measurements: 'all' can only be used alone, without other EID numbers");
            }
        }
    }
}

void SpdmdApp::connectMCTP(const std::string& sockPath)
{
    if (!context.isIOPathRegistered(sockPath))
    {
        std::cout << "connectMCTP() " << sockPath << std::endl;
        auto mctpIo = std::make_shared<spdmcpp::MctpIoClass>(getLog());
        if (mctpIo->createSocket(sockPath))
        {
            int fd = mctpIo->getSocket();

            auto streamDesc =
                std::make_unique<boost::asio::posix::stream_descriptor>(getIo(),
                                                                        fd);
            auto rearmPtr = std::make_shared<
                std::function<void(boost::asio::posix::stream_descriptor*)>>();
            *rearmPtr = [this, mctpIo, sockPath, rearmPtr](
                            boost::asio::posix::stream_descriptor* desc) {
                desc->async_wait(
                    boost::asio::posix::stream_descriptor::wait_read,
                    [this, desc, mctpIo, sockPath,
                     rearmPtr](const boost::system::error_code& ec) {
                        if (!ec)
                        {
                            mctpCallback(EPOLLIN, *mctpIo);
                            (*rearmPtr)(desc);
                        }
                        else
                        {
                            auto& log = getLog();
                            if (log.logLevel >= spdmcpp::LogClass::Level::Error)
                            {
                                log.iprint(
                                    "Error on MCTP async_wait for sockPath ");
                                log.iprint(sockPath);
                                log.iprint(": ");
                                log.iprintln(ec.message());
                            }
                        }
                    });
            };

            (*rearmPtr)(streamDesc.get());
            mctpEvents[sockPath] = std::move(streamDesc);
            context.registerIo(mctpIo, sockPath);
        }
        else
        {
            if (getLog().logLevel >= spdmcpp::LogClass::Level::Warning)
            {
                getLog().iprintln("Unable to connect to socket");
            }
        }
    }
    if (mctpEvents.empty())
    {
        throw std::runtime_error("Couldn't connect to any MCTP endpoint");
    }
}

void SpdmdApp::connectMCTP()
{
    auto io = std::make_shared<spdmcpp::MctpIoClass>(getLog());
    if (io->createSocket())
    {
        int fd = io->getSocket();

        auto streamDesc =
            std::make_unique<boost::asio::posix::stream_descriptor>(getIo(),
                                                                    fd);
        auto rearmPtr = std::make_shared<
            std::function<void(boost::asio::posix::stream_descriptor*)>>();
        *rearmPtr = [this, io,
                     rearmPtr](boost::asio::posix::stream_descriptor* desc) {
            desc->async_wait(
                boost::asio::posix::stream_descriptor::wait_read,
                [this, desc, io,
                 rearmPtr](const boost::system::error_code& ec) {
                    if (!ec)
                    {
                        mctpCallback(EPOLLIN, *io);
                        (*rearmPtr)(desc);
                    }
                    else
                    {
                        auto& log = getLog();
                        if (log.logLevel >= spdmcpp::LogClass::Level::Error)
                        {
                            log.iprint("Error on MCTP async_wait for afPath: ");
                            log.iprintln(ec.message());
                        }
                    }
                });
        };

        (*rearmPtr)(streamDesc.get());
        afMctpEvent = std::move(streamDesc);
        context.registerIo(io);
    }
    else
    {
        if (getLog().logLevel >= spdmcpp::LogClass::Level::Warning)
        {
            getLog().iprintln("Unable to connect to socket");
        }
    }
}

bool SpdmdApp::needRecreateResponder(const std::string& currMedium,
                                     const std::string& newMedium,
                                     const std::string& currBinding,
                                     const std::string& newBinding)
{
    auto currMediumPriority = mediumPriority.find(currMedium);
    auto newMediumPriority = mediumPriority.find(newMedium);

    if (currMediumPriority == mediumPriority.end() ||
        newMediumPriority == mediumPriority.end())
    {
        auto& log = getLog();
        if (log.logLevel >= spdmcpp::LogClass::Level::Error)
        {
            log.iprint("medium type priority not found in the map");
            log.println("Current Medium: " + currMedium + "(" +
                        std::to_string(currMediumPriority->second) +
                        "), New Medium: " + newMedium + "(" +
                        std::to_string(newMediumPriority->second) + ")");
        }
        return false;
    }

    // If medium priorities are different, recreate if new medium has
    // higher priority (lower number)
    if (currMediumPriority->second != newMediumPriority->second)
    {
        return newMediumPriority->second < currMediumPriority->second;
    }

    // If medium priorities are the same, check binding type priorities
    auto currBindingPriority = bindingPriority.find(currBinding);
    auto newBindingPriority = bindingPriority.find(newBinding);

    if (currBindingPriority == bindingPriority.end() ||
        newBindingPriority == bindingPriority.end())
    {
        auto& log = getLog();
        if (log.logLevel >= spdmcpp::LogClass::Level::Error)
        {
            log.iprint("binding type priority not found in the map ");
            log.println("Current Binding: " + currBinding + "(" +
                        std::to_string(currBindingPriority->second) +
                        "), New Binding: " + newBinding + "(" +
                        std::to_string(newBindingPriority->second) + ")");
        }
        return false;
    }

    // If both medium and binding types are same, it indicates that the
    // inventory objects are recreated. Recreate the responder to refresh the
    // object.
    return newBindingPriority->second <= currBindingPriority->second;
}

void SpdmdApp::discoveryUpdateResponder(const dbus_api::ResponderArgs& respArg)
{

    const auto it = resp_discovery.find(respArg.uuid);
    if (it == std::end(resp_discovery))
    {
        // Discovery object by UUID not found select first
        resp_discovery.emplace(respArg.uuid, respArg);
        createResponder(respArg);
        reportNotice("Create first responder UUID: " + respArg.uuid +
                     " EID: " + std::to_string(respArg.eid));
    }
#ifndef MCTP_IN_KERNEL
    else
    {
        // Discovery found recreate if needed
        if (!respArg.medium.empty() && !it->second.medium.empty())
        {
            if (needRecreateResponder(it->second.medium, respArg.medium,
                                      it->second.bindingType,
                                      respArg.bindingType))
            {
                reportNotice("Recreate responder UUID: " + respArg.uuid +
                             " EID: " + std::to_string(respArg.eid));
                responders[it->second.eid].reset();
                resp_discovery.erase(it);
                resp_discovery.emplace(respArg.uuid, respArg);
                createResponder(respArg);
            }
            else
            {
                reportNotice("Lower priority responder not need create: " +
                             it->first);
            }
        }
        else
        {
            reportNotice("Unknown transport medium when recreate: " +
                         it->first);
        }
    }
#endif
}

void SpdmdApp::createResponder(const dbus_api::ResponderArgs& args)
{
    SPDMCPP_LOG_TRACE_FUNC(getLog());
    if (args.eid >= responders.size())
    {
        responders.resize(args.eid + 1);
    }

    string msg = "Creating SPDM object for a responder with EID = " +
                 to_string(args.eid);
    reportNotice(msg);

    std::string path(spdmRootObjectPath);
    { // construct responder path
        path += '/';
        auto sub = args.inventoryPath.filename();
        if (!sub.empty())
        {
            path += sub;
        }
        else
        { // fallback to eid for local-testing
            path += std::to_string(args.eid);
        }
    }
#ifdef MCTP_IN_KERNEL
    responders[args.eid] = std::make_unique<dbus_api::Responder>(
        *this, path, args.eid, args.mctpPath, args.inventoryPath,
        TransportMedium::None, args.socketPath);
#else

    if (!args.medium.empty())
    {
        const std::string& mediumType =
            args.medium.empty()
                ? "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.PCIe"
                : args.medium;

        responders[args.eid] = std::make_unique<dbus_api::Responder>(
            *this, path, args.eid, args.mctpPath, args.inventoryPath,
            mediumType, args.bindingType, args.socketPath);
    }
    else
    {
        reportError("Unable to determine responder type"
                    "EID = " +
                    std::to_string(args.eid) + " " +
                    "MCTPPATH = " + args.mctpPath.str + " " +
                    "INVENTORYPATH = " + args.inventoryPath.str);
        return;
    }
#endif

#if FETCH_SERIALNUMBER_FROM_RESPONDER != 0
    responders[args.eid]->refreshSerialNumber();
#endif
    autoMeasure(args.eid);
}

void SpdmdApp::setupMeasurementDelay()
{
    if (!measureOnDiscovery)
    {
        return;
    }
    if (measureOnDiscoveryDelay == std::chrono::seconds(0))
    {
        // measureOnDiscoveryActive should've already been set,
        // because initial discovery happens earlier
        SPDMCPP_ASSERT(measureOnDiscoveryActive);
        return;
    }
    measurementDelayTimer =
        std::make_unique<boost::asio::steady_timer>(getIo());
    measurementDelayTimer->expires_after(measureOnDiscoveryDelay);
    measurementDelayTimer->async_wait(
        [this](const boost::system::error_code& ec) {
            if (!ec)
            {
                measurementDelayCallback();
            }
            else
            {
                auto& log = getLog();
                if (log.logLevel >= spdmcpp::LogClass::Level::Warning)
                {
                    log.print("Measurement delay timer error: ");
                    log.println(ec.message());
                }
            }
        });
}

void SpdmdApp::mctpCallback(uint32_t revents, spdmcpp::MctpIoClass& mctpIo)
{

    SPDMCPP_LOG_TRACE_FUNC(getLog());

    if (!(revents & EPOLLIN))
    {
        return;
    }

    {
        auto rs = mctpIo.read(packetBuffer);
        if (rs != spdmcpp::RetStat::OK)
        {
            getLog().println(
                "SpdmdApp::IO read failed likely due to broken socket connection, quitting!");
            std::exit(1);
            return;
        }
    }

    uint8_t eid = 0;
    {
        spdmcpp::TransportClass::LayerState lay; // TODO double decode
        auto rs = spdmcpp::MctpTransportClass::peekEid(packetBuffer, lay, eid);

        SPDMCPP_LOG_TRACE_RS(getLog(), rs);
        switch (rs)
        {
            case spdmcpp::RetStat::OK:
                break;
            case spdmcpp::RetStat::ERROR_BUFFER_TOO_SMALL:
                getLog().print("SpdmdApp::IO: packet size = ");
                getLog().print(packetBuffer.size());
                getLog().println(" is too small to be a valid SPDM packet");
                return;
            default:
                getLog().print(
                    "SpdmdApp::IO peekEid returned unexpected error: ");
                getLog().println(rs);
                return;
        }
    }
    if (eid >= responders.size())
    {
        getLog().println(
            "SpdmdApp::IO received message from EID=" + std::to_string(eid) +
            " outside of responder array size=" +
            std::to_string(responders.size()));
        return;
    }
    if (!responders[eid])
    {
        getLog().println(
            "SpdmdApp::IO received message from EID=" + std::to_string(eid) +
            " while responder class is not created");
    }
    else
    {
        auto& resp = responders[eid];
        spdmcpp::EventReceiveClass ev(packetBuffer);
        resp->handleEvent(ev);
    }
}

void SpdmdApp::measurementDelayCallback()
{
    measureOnDiscoveryActive = true;
    for (size_t eid = 0; eid < responders.size(); ++eid)
    {
        if (responders[eid])
        {
            autoMeasure(eid);
        }
    }
}

bool SpdmdApp::autoMeasure(uint8_t eid) const
{
    if (!shouldMeasureEID(eid))
    {
        return false;
    }
    responders[eid]->refresh(0, std::vector<uint8_t>(), std::vector<uint8_t>(),
                             0);
    return true;
}

} // namespace spdmd

int main(int argc, char** argv)
{
    int returnCode = 0;

    try
    {
        SpdmdApp spdmApp;

        spdmApp.setupCli(argc, argv);

        spdmApp.connectDBus(spdmDefaultService);
#ifdef MCTP_IN_KERNEL
        spdmApp.connectMCTP();
#endif

        std::unique_ptr<MctpDiscovery> mctpDiscoveryHandler =
            std::make_unique<MctpDiscovery>(spdmApp);

        spdmApp.setupMeasurementDelay();

        auto& conn = spdmApp.getConn();
        sdbusplus::server::manager_t objManager(conn, spdmRootObjectPath);
        returnCode = spdmApp.loop();
    }
    catch (const std::exception& e)
    {
        std::cerr << "exception reached main '" << e.what() << std::endl;
        returnCode = -2;
    }

    return returnCode;
}
