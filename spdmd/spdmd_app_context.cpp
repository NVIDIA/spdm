#include "spdmd_app_context.hpp"
#include <fstream>

namespace spdmd
{
    using json = nlohmann::json;

    SpdmdAppContext::SpdmdAppContext(sdeventplus::Event&& e, sdbusplus::bus::bus&& b,
                     std::ostream& logOutStream) :
        event(std::move(e)),
        bus(std::move(b)), log(logOutStream)
    {
        try
        {
            std::ifstream ifs(confFile);
            conf = json::parse(ifs);
        }
        catch(json::parse_error& e)
        {
            logOutStream << "Unable to open config file: "  << e.what() << std::endl;
        }
    }

    bool SpdmdAppContext::shouldMeasureEID(uint8_t eid) const
    /** @brief call to check if the given EID should be measured right now */
    {
        if (measureOnDiscoveryActive)
        {
            if (cachedMeasurements.empty())
            {
                return true; // this means "all" was selected
            }
            if (cachedMeasurements.contains(eid))
            {
                return true;
            }
        }

        return false;
    }

    bool SpdmdAppContext::reportLog(obmcprj::Logging::server::Entry::Level severity,
                   const string& message)
    {
        if ((severity == obmcprj::Logging::server::Entry::Level::Error) &&
            (log.logLevel >= spdmcpp::LogClass::Level::Error))
        {
            std::cerr << message << std::endl;
        }
        else if ((severity == obmcprj::Logging::server::Entry::Level::Notice) &&
                 (log.logLevel >= spdmcpp::LogClass::Level::Notice))
        {
            log.getOstream() << message << std::endl;
        }

#ifdef USE_PHOSPHOR_LOGGING
        auto method = bus.new_method_call(
            "xyz.openbmc_project.Logging", "/xyz/openbmc_project/logging",
            "xyz.openbmc_project.Logging.Create", "Create");

        method.append(message);

        auto severityS = obmcprj::Logging::server::convertForMessage(severity);

        method.append(severityS);

        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        string telemetries = std::ctime(&time);
        telemetries.resize(telemetries.size() - 1);

        string resolution = (severity < obmcprj::Logging::server::Entry::Level::Warning)
                                ? "Contact NVIDIA Support"
                                : "";

        method.append(std::array<std::pair<std::string, std::string>, 3>(
            {{{"xyz.openbmc_project.Logging.Entry.Resolution", resolution},
              {"DEVICE_EVENT_DATA", telemetries},
              {"namespace", "spdmd"}}}));

        try
        {
            auto reply = bus.call(method);
            std::vector<std::tuple<uint32_t, std::string,
                                   sdbusplus::message::object_path>>
                users;
            reply.read(users);
            for (auto& user : users)
            {
                std::cerr << std::get<std::string>(user) << "\n";
            }
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            std::cerr << "ERROR CREATING LOG " << e.what() << "\n";
            return false;
        }
#endif

        return true;
    }
}

