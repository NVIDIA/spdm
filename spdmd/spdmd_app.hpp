#pragma once

#include "utils.hpp"
#include "spdmd_app_context.hpp"
#include "dbus_impl_responder.hpp"

#include "spdmcpp/context.hpp"
#include "spdmcpp/mctp_support.hpp"
#include "spdmcpp/log.hpp"

#include <sdeventplus/event.hpp>
#include <sdeventplus/source/io.hpp>

using namespace std;
using namespace spdmd;
using namespace spdmcpp;
using namespace sdbusplus;

namespace spdmd
{

class SpdmdApp : SpdmdAppContext
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
    int setupCli(int argc, char** argv);

    /** @brief Connect SPDM daemon to D-bus
     *
     */
    void connectDBus();

    /** @brief Connect SPDM daemon to MCTP
     *
     */
    bool connectMCTP();

    /** @brief Create new Responder object
     *
     */
    bool createResponder(uint8_t eid);

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

    /** @brief log object used to log debug messages */
    spdmcpp::LogClass log;

  private:
    /** @brief verbose - debug level for SPDM daemon */
    int verbose{0};

    /** @brief MCTP interface auxiliary object - used for transmission purposes over MCTP */
    spdmcpp::MCTP_IOClass mctpIo;

    /** @brief Event handlar for MCTP events - used for transmission purposes over MCTP */
    sdeventplus::source::IO* mctpEvent = nullptr;

    /** @brief Array of all responder objects, managed by SPDM daemon */
    std::vector<dbus_api::Responder*> responders;

    /** @brief Buffer for packets received from responders over MCTP */
    std::vector<uint8_t> packetBuffer;
};

} // namespace spdmd
