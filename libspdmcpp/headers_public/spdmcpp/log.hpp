
#pragma once

#include "endianness.hpp"
#include "enum.hpp"
#include "flag.hpp"
#include "retstat.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <ostream>
#include <span>
#include <vector>

namespace spdmcpp
{

/** @class LogClass
 *  @brief Class for detailed logging of events
 *  @details Supports indentation and is meant to be used per-thread.
 *  print() functions just print the data passed as the argument
 *  iprint() template indents accordingly then prints data
 *  println() template prints data then a newline
 *  iprintln() template indents, prints data, then a newline
 */
class LogClass
{
  public:
    /** @brief Log level definition - the same as for phosphor-logging log
     * levels */
    enum class Level
    {
        Emergency = 0,
        Alert = 1,
        Critical = 2,
        Error = 3,
        Warning = 4,
        Notice = 5,
        Informational = 6,
        Debug = 7,
    };

    explicit LogClass(std::ostream& ostream) :
        logLevel(Level::Emergency), Stream(&ostream)
    {}

    LogClass(std::ostream& ostream, Level reportLevel) :
        logLevel(reportLevel), Stream(&ostream)
    {}

    LogClass(const LogClass&) = delete;
    LogClass& operator=(const LogClass&) = delete;
    LogClass(LogClass&&) = delete;
    LogClass& operator=(LogClass&&) = delete;
    ~LogClass() = default;

    void setLogLevel(Level reportLevel)
    {
        logLevel = reportLevel;
    }

    // TODO definitely more helpers needed, time-stamping?!

    /** Various print variants */
    void print(char* str)
    {
        getOstream() << str;
    }
    void print(const char* str)
    {
        getOstream() << str;
    }
    void print(const std::string& str)
    {
        getOstream() << str;
    }

    void print(char value)
    {
        getOstream() << value;
    }

    void print(uint8_t value)
    {
        getOstream() << (int)value;
    }
    void print(uint16_t value)
    {
        getOstream() << value;
    }
    void print(uint32_t value)
    {
        getOstream() << value;
    }
    void print(uint64_t value)
    {
        getOstream() << value;
    }

    void print(int8_t value)
    {
        getOstream() << (int)value;
    }
    void print(int16_t value)
    {
        getOstream() << value;
    }
    void print(int32_t value)
    {
        getOstream() << value;
    }
    void print(int64_t value)
    {
        getOstream() << value;
    }

    void print(std::span<const uint8_t, std::dynamic_extent> arr)
    {
        std::ostream& ostr = getOstream();
        std::ios_base::fmtflags oldf = ostr.flags();
        ostr.setf(std::ios_base::hex | std::ios_base::right |
                      std::ios_base::showbase,
                  std::ios_base::basefield);
        // 			ostr.width(8);
        // 			ostr << std::setw(8);
        ostr.fill('0');
        for (size_t i = 0; i < arr.size();)
        {
            ostr.width(2);
            // NOLINTNEXTLINE cppcoreguidelines-pro-bounds-pointer-arithmetic
            ostr << (int)arr[i];
            ++i;
            /* longer spaces for easier counting?
            if (i % 16 == 0)
                ostr << "    ";
            if (i % 8 == 0)
                ostr << "   ";
            else if (i % 4 == 0)
                ostr << "  ";
            else*/
            ostr << " ";
        }
        //	ostr << std::dec;
        ostr.setf(oldf);
    }

    template <size_t N>
    void print(const std::array<uint8_t, N>& array)
    {
        print(std::span<const uint8_t, std::dynamic_extent>(array));
    }

    void print(const std::vector<uint8_t>& vec)
    {
        print(std::span(vec));
    }

    void endl()
    {
        getOstream() << std::endl;
    }

    template <typename T>
    void print(const T& value)
    {
        getOstream() << get_cstr(value);
    } // TODO atm this is for enums, but it's likely to be a problem, it also
      // results in confusing errors when calling with a "not yet supported"
      // type

    template <typename... Targs>
    void println(Targs... fargs)
    {
        print(fargs...);
        endl();
    }
    template <typename... Targs>
    void iprint(Targs... fargs)
    {
        printIndent();
        print(fargs...);
    }
    template <typename... Targs>
    void iprintln(Targs... fargs)
    {
        iprint(fargs...);
        endl();
    }

    /** @brief helper which prints the current indentation
     *  @details typically shouldn't be used, use iprint(data) instead
     */
    void printIndent()
    {
        auto i = Indentation;
        while (i--)
        {
            getOstream().put('\t');
        }
    }

    /** @brief function for increasing the indentation level
     *  @details typically shouldn't be used, use SPDMCPP_LOG_INDENT instead
     */
    void indent()
    {
        ++Indentation;
    }

    /** @brief function for decreasing the indentation level
     *  @details typically shouldn't be used, use SPDMCPP_LOG_INDENT instead
     */
    void unindent()
    {
        if (Indentation)
        {
            --Indentation;
        }
        else
        {}
    }

    std::ostream& getOstream()
    {
        return *Stream;
    }

    Level logLevel;

  private:
    uint16_t Indentation = 0;

    std::ostream* Stream;
}; // class LogClass

/** @class IndentHelper
 *  @brief Class for automatic indentation of blocks of code
 *  @details Typically SPDMCPP_LOG_INDENT(log) should be used instead for
 * convenience
 */
class IndentHelper
{
  public:
    IndentHelper() = delete;
    explicit IndentHelper(LogClass& log) : Log(log)
    {
        Log.indent();
    }
    ~IndentHelper()
    {
        Log.unindent();
    }

    IndentHelper(const IndentHelper&) = delete;
    IndentHelper& operator=(const IndentHelper&) = delete;
    IndentHelper(IndentHelper&&) = delete;
    IndentHelper& operator=(IndentHelper&&) = delete;

  private:
    LogClass& Log;
}; // class IndentHelper

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SPDMCPP_LOG_INDENT(log) IndentHelper log_indent_helper_##__LINE__((log))

/** @class TraceHelper
 *  @brief Helper class for automatic tracing of function calls with indentation
 *  @details Typically SPDMCPP_LOG_TRACE_FUNC(log) or
 * SPDMCPP_LOG_TRACE_BLOCK(log) should be used instead
 */
class TraceHelper
{
  public:
    TraceHelper(LogClass& log, const std::string& func) :
        Log(log), Function(func + "()")
    {
        Log.iprint(Function);
        Log.println(" START:");
        Log.indent();
    }
    TraceHelper(LogClass& log, const std::string& func, const std::string& file,
                uint32_t line) :
        Log(log),
        Function(func + "() BLOCK")
    {
        Log.iprint(Function);
        Log.print(" START: @ ");
        Log.print(file);
        Log.print(" : ");
        Log.println(line);
        Log.indent();
    }
    ~TraceHelper()
    {
        Log.unindent();
        Log.iprint(Function);
        Log.println(" END");
    }

    TraceHelper(const TraceHelper&) = delete;
    TraceHelper& operator=(const TraceHelper&) = delete;
    TraceHelper(TraceHelper&&) = delete;
    TraceHelper& operator=(TraceHelper&&) = delete;

  private:
    LogClass& Log;
    std::string Function;
}; // class TraceHelper

// clang-format off

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SPDMCPP_LOG_TRACE_FUNC(log)                                               \
    if ((log).logLevel >= spdmcpp::LogClass::Level::Debug)                        \
    {                                                                             \
        spdmcpp::TraceHelper log_trace_helper_##__LINE__(                         \
            (log),                                                                \
            (__func__)); /*NOLINT cppcoreguidelines-pro-bounds-array-to-pointer-decay*/ \
    }

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SPDMCPP_LOG_TRACE_BLOCK(log)                                             \
    if ((log).logLevel >= spdmcpp::LogClass::Level::Debug)                       \
    {                                                                            \
        spdmcpp::TraceHelper log_trace_helper_##__LINE__(                        \
            (log),                                                               \
            (__func__), /*NOLINT cppcoreguidelines-pro-bounds-array-to-pointer-decay*/ \
            __FILE__, __LINE__);                                                 \
    }

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SPDMCPP_LOG_TRACE_RS(log, rs)                                            \
    if ((log).logLevel >= spdmcpp::LogClass::Level::Debug)                       \
    {                                                                            \
        (log).iprint(#rs " = ");                                                 \
        (log).print((rs));                                                       \
        (log).print("; in: ");                                                   \
        (log).print((__func__)); /*NOLINT cppcoreguidelines-pro-bounds-array-to-pointer-decay*/ \
        (log).print("() @ ");                                                    \
        (log).print(__FILE__);                                                   \
        (log).print(" : ");                                                      \
        (log).println(__LINE__);                                                 \
    }

// clang-format on

} // namespace spdmcpp
