#pragma once

#include "dbus_impl_responder.hpp"
#include "spdmcpp/context.hpp"
#include "spdmcpp/log.hpp"
#include "spdmcpp/mctp_support.hpp"
#include "spdmd_app_context.hpp"
#include "utils.hpp"

#include <sdeventplus/event.hpp>
#include <sdeventplus/source/io.hpp>

#include <memory>

using namespace std;
using namespace spdmd;
using namespace spdmcpp;
using namespace sdbusplus;

namespace spdmd
{

class SpdmdApp : public SpdmdAppContext
{
  public:
    SpdmdApp(const SpdmdApp&) = delete;
    SpdmdApp(SpdmdApp&&) = delete;
    SpdmdApp& operator=(const SpdmdApp&) = delete;
    SpdmdApp& operator=(SpdmdApp&&) = delete;
    ~SpdmdApp();

    /** @brief Constructs the SPDM daemon
     *
     */
    SpdmdApp();

    /** @brief Setup CLI for SPDM daemon
     *
     */
    void setupCli(int argc, char** argv);

    /** @brief Connect SPDM daemon to D-bus
     *
     */
    void connectDBus();

    /** @brief Connect SPDM daemon to MCTP
     *
     */
    void connectMCTP();

    /** @brief Create new Responder object
     *
     */
    void createResponder(uint8_t eid,
                         const sdbusplus::message::object_path& mctpPath,
                         const sdbusplus::message::object_path& inventoryPath);

    /** @brief Sets up the automatic measurement delay according to commandline
     * parameters
     */
    void setupMeasurementDelay();

    /** @brief Enter SPDM daemon into forever loop
     *
     */
    int loop();

    /** @brief Get reference to the used d-bus object
     *
     */
    sdbusplus::bus::bus& getBus()
    {
        return SpdmdAppContext::bus;
    }

    /** @brief Get reference to logger object
     *
     */
    spdmcpp::LogClass& getLog()
    {
        return SpdmdAppContext::log;
    }

  private:
    /** @brief verbose - debug level for SPDM daemon */
    spdmcpp::LogClass::Level verbose = spdmcpp::LogClass::Level::Emergency;

    /** @brief MCTP interface auxiliary object - used for transmission purposes
     * over MCTP */
    spdmcpp::MctpIoClass mctpIo;

    /** @brief Event handlar for MCTP events - used for transmission purposes
     * over MCTP */
    sdeventplus::source::IO* mctpEvent = nullptr;

    /** @brief Array of all responder objects, managed by SPDM daemon */
    std::vector<dbus_api::Responder*> responders;

    /** @brief Buffer for packets received from responders over MCTP */
    std::vector<uint8_t> packetBuffer;

    /** @brief Timer for handling the measurement delay
     */
    std::unique_ptr<Timer> measurementDelayTimer;

    /** @brief Callback for the automatic measurement delay
     */
    void measurementDelayCallback();

    /** @brief checks if the given eid should be measured and issues a refresh
     *  @returns true if refresh was called, false otherwise
     */
    bool autoMeasure(uint8_t eid) const;
};

} // namespace spdmd
