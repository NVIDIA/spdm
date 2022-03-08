#pragma once

#include "spdmcpp/context.hpp"
#include "spdmcpp/log.hpp"

#include <sdbusplus/bus.hpp>
#include <sdeventplus/event.hpp>

namespace spdmd
{

class SpdmdAppContext
{
  public:
    spdmcpp::ContextClass context;
    sdeventplus::Event event;
    sdbusplus::bus::bus bus;

    SpdmdAppContext(sdeventplus::Event&& e, sdbusplus::bus::bus&& b) :
        event(std::move(e)), bus(std::move(b))
    {}
};

} // namespace spdmd
