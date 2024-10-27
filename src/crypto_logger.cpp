// crypto_logger.cpp
#include "crypto_logger.hpp"

namespace crypto {

LogLevel CryptoLogger::current_level = LogLevel::INFO;
bool CryptoLogger::debug_mode = false;
bool CryptoLogger::trace_operations = false;
std::mutex CryptoLogger::log_mutex;

} // namespace crypto