// crypto_logger.hpp
#pragma once
#include <iostream>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <exception>
#include <mutex>

namespace crypto
{

    enum class LogLevel
    {
        TRACE = 0,   // Most detailed level - internal transformations
        DEBUG = 1,   // Detailed information for debugging
        INFO = 2,    // General information about operations
        WARNING = 3, // Warning messages
        ERROR = 4,   // Error messages
        CRITICAL = 5 // Critical errors that may compromise security
    };

    class CryptoLogger
    {
    private:
        static LogLevel current_level;
        static bool debug_mode;
        static bool trace_operations;
        static std::mutex log_mutex; // Thread safety for logging

        static std::string get_current_time()
        {
            auto now = std::chrono::system_clock::now();
            auto in_time_t = std::chrono::system_clock::to_time_t(now);
            std::stringstream ss;
            ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X");
            return ss.str();
        }

        static std::string level_to_string(LogLevel level)
        {
            switch (level)
            {
            case LogLevel::TRACE:
                return "TRACE";
            case LogLevel::DEBUG:
                return "DEBUG";
            case LogLevel::INFO:
                return "INFO";
            case LogLevel::WARNING:
                return "WARN";
            case LogLevel::ERROR:
                return "ERROR";
            case LogLevel::CRITICAL:
                return "CRIT";
            default:
                return "UNKNOWN";
            }
        }

        static std::string format_message(const std::string &message, LogLevel level)
        {
            std::stringstream ss;
            ss << "[" << get_current_time() << "] "
               << std::setw(5) << level_to_string(level) << ": "
               << message;
            return ss.str();
        }

    public:
        static void set_log_level(LogLevel level)
        {
            std::lock_guard<std::mutex> lock(log_mutex);
            current_level = level;
        }

        static void set_debug_mode(bool mode)
        {
            std::lock_guard<std::mutex> lock(log_mutex);
            debug_mode = mode;
            current_level = mode ? LogLevel::DEBUG : LogLevel::INFO;
        }

        static void set_trace_operations(bool trace)
        {
            std::lock_guard<std::mutex> lock(log_mutex);
            trace_operations = trace;
            if (trace && current_level > LogLevel::TRACE)
            {
                current_level = LogLevel::TRACE;
            }
        }

        static LogLevel get_log_level()
        {
            return current_level;
        }

        static bool get_debug_mode()
        {
            return debug_mode;
        }

        static bool should_log(LogLevel level)
        {
            return static_cast<int>(level) >= static_cast<int>(current_level);
        }

        static void log(const std::string &message, LogLevel level = LogLevel::INFO)
        {
            if (should_log(level))
            {
                if (level == LogLevel::TRACE && !trace_operations)
                {
                    return;
                }
                std::lock_guard<std::mutex> lock(log_mutex);
                std::cout << format_message(message, level) << std::endl;
            }
        }

        static void trace(const std::string &message)
        {
            log(message, LogLevel::TRACE);
        }

        static void debug(const std::string &message)
        {
            log(message, LogLevel::DEBUG);
        }

        static void info(const std::string &message)
        {
            log(message, LogLevel::INFO);
        }

        static void warning(const std::string &message)
        {
            log(message, LogLevel::WARNING);
        }

        static void error(const std::string &message)
        {
            log(message, LogLevel::ERROR);
        }

        static void critical(const std::string &message)
        {
            log(message, LogLevel::CRITICAL);
        }

        static void log_exception(const std::exception &e, const std::string &context = "")
        {
            std::stringstream ss;
            ss << "Exception caught";
            if (!context.empty())
            {
                ss << " in " << context;
            }
            ss << ": " << e.what();
            error(ss.str());
        }

        // Test helper methods
        static void set_test_mode(bool verbose = false)
        {
            std::lock_guard<std::mutex> lock(log_mutex);
            if (verbose)
            {
                current_level = LogLevel::TRACE;
                trace_operations = true;
                debug_mode = true;
            }
            else
            {
                current_level = LogLevel::INFO;
                trace_operations = false;
                debug_mode = false;
            }
        }

        static void log_state(const uint8_t state[4][4], const std::string &step, LogLevel level = LogLevel::TRACE)
        {
            if (should_log(level))
            {
                std::stringstream ss;
                ss << "\nState after " << step << ":\n";
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        ss << std::hex << std::setw(2) << std::setfill('0')
                           << static_cast<int>(state[i][j]) << " ";
                    }
                    ss << "\n";
                }
                log(ss.str(), level);
            }
        }

        static void log_bytes(const uint8_t *data, size_t length,
                              const std::string &prefix, LogLevel level = LogLevel::TRACE)
        {
            if (should_log(level))
            {
                std::stringstream ss;
                ss << prefix << ": ";
                for (size_t i = 0; i < length; i++)
                {
                    ss << std::hex << std::setw(2) << std::setfill('0')
                       << static_cast<int>(data[i]) << " ";
                }
                log(ss.str(), level);
            }
        }

        static void log_state_array(const uint8_t state[4][4], const std::string &step, LogLevel level = LogLevel::TRACE)
        {
            if (!should_log(level))
                return;

            std::lock_guard<std::mutex> lock(log_mutex);
            std::stringstream ss;

            ss << "\nState array (" << step << "):\n";
            // Print column indices
            ss << "     0  1  2  3\n";
            ss << "   +------------\n";

            for (int row = 0; row < 4; row++)
            {
                ss << row << " | ";
                for (int col = 0; col < 4; col++)
                {
                    ss << std::hex << std::setw(2) << std::setfill('0')
                       << static_cast<int>(state[row][col]) << " ";
                }
                ss << "\n";
            }
            log(ss.str(), level);
        }

        static void log_hex_array(const uint8_t *data, size_t length,
                                  const std::string &description, size_t line_width = 16,
                                  LogLevel level = LogLevel::TRACE)
        {
            if (!should_log(level))
                return;

            std::lock_guard<std::mutex> lock(log_mutex);
            std::stringstream ss;

            ss << "\n"
               << description << " (" << std::dec << length << " bytes):\n";

            for (size_t i = 0; i < length; i++)
            {
                if (i % line_width == 0)
                {
                    if (i > 0)
                        ss << "\n";
                    ss << std::hex << std::setw(4) << std::setfill('0') << i << ": ";
                }
                ss << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<int>(data[i]) << " ";
            }
            ss << "\n";
            log(ss.str(), level);
        }

        static void log_round_key(const std::vector<uint8_t> &roundKey, size_t round,
                                  LogLevel level = LogLevel::TRACE)
        {
            if (!should_log(level))
                return;

            std::lock_guard<std::mutex> lock(log_mutex);
            std::stringstream ss;

            ss << "\nRound " << std::dec << round << " Key:\n";
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    ss << std::hex << std::setw(2) << std::setfill('0')
                       << static_cast<int>(roundKey[round * 16 + col * 4 + row]) << " ";
                }
                ss << "\n";
            }
            log(ss.str(), level);
        }
    };

} // namespace crypto