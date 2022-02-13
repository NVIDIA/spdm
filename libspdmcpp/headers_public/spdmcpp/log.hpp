
#pragma once

#include <spdmcpp/endianness.hpp>
#include <spdmcpp/enum.hpp>
#include <spdmcpp/flag.hpp>
#include <spdmcpp/retstat.hpp>

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <ostream>
#include <vector>

namespace spdmcpp
{

class LogClass
{
  public:
    // TODO definitely more helpers needed, time-stamping?!

    void print(const char* str)
    {
        get_ostream() << str;
    }
    void print(const std::string& str)
    {
        get_ostream() << str;
    }

    void print(char value)
    {
        get_ostream() << value;
    }

    void print(uint8_t value)
    {
        get_ostream() << (int)value;
    }
    void print(uint16_t value)
    {
        get_ostream() << value;
    }
    void print(uint32_t value)
    {
        get_ostream() << value;
    }
    void print(uint64_t value)
    {
        get_ostream() << value;
    }

    void print(int8_t value)
    {
        get_ostream() << (int)value;
    }
    void print(int16_t value)
    {
        get_ostream() << value;
    }
    void print(int32_t value)
    {
        get_ostream() << value;
    }
    void print(int64_t value)
    {
        get_ostream() << value;
    }

    void print(const uint8_t* arr, size_t num)
    {
        std::ostream& ostr = get_ostream();
        std::ios_base::fmtflags oldf = ostr.flags();
        ostr.setf(std::ios_base::hex | std::ios_base::right |
                      std::ios_base::showbase,
                  std::ios_base::basefield);
        // 			ostr.width(8);
        // 			ostr << std::setw(8);
        ostr.fill('0');
        for (size_t i = 0; i < num;)
        {
            ostr.width(2);
            ostr << (int)arr[i]; // TODO something more optimal
            ++i;
            /*	if (i % 16 == 0)
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

    void endl()
    {
        get_ostream() << std::endl;
    }

    template <typename T>
    void print(const T& value)
    {
        get_ostream() << get_cstr(value);
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
        print_indent();
        print(fargs...);
    }
    template <typename... Targs>
    void iprintln(Targs... fargs)
    {
        iprint(fargs...);
        endl();
    }

    void print_indent()
    {
        auto i = Indentation;
        while (i--)
            get_ostream().put('\t');
    }
    void indent()
    {
        ++Indentation;
    }
    void unindent()
    {
        if (Indentation)
        {
            --Indentation;
        }
        else
        {}
    }

    std::ostream& get_ostream()
    {
        return *Stream;
    }

    LogClass(std::ostream& ostream) : Stream(&ostream)
    {}

  private:
    uint16_t Indentation = 0;

    std::ostream* Stream;
};

class IndentHelper
{
  public:
    IndentHelper() = delete;
    IndentHelper(LogClass& log) : Log(log)
    {
        Log.indent();
    }
    ~IndentHelper()
    {
        Log.unindent();
    }

  private:
    LogClass& Log;
};

#define SPDMCPP_LOG_INDENT(log) IndentHelper log_indent_helper_##__LINE__((log))

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

  private:
    LogClass& Log;
    std::string Function;
};

#define SPDMCPP_LOG_TRACE_FUNC(log)                                            \
    TraceHelper log_trace_helper_##__LINE__((log), __func__)
#define SPDMCPP_LOG_TRACE_BLOCK(log)                                           \
    TraceHelper log_trace_helper_##__LINE__((log), __func__, __FILE__, __LINE__)
#define SPDMCPP_LOG_TRACE_RS(log, rs)                                          \
    do                                                                         \
    {                                                                          \
        (log).iprint(#rs " = ");                                               \
        (log).print((rs));                                                     \
        (log).print("; in: ");                                                 \
        (log).print(__func__);                                                 \
        (log).print("() @ ");                                                  \
        (log).print(__FILE__);                                                 \
        (log).print(" : ");                                                    \
        (log).println(__LINE__);                                               \
    } while (false)

} // namespace spdmcpp
