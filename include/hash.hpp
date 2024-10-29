// hash.hpp
#pragma once

#include <vector>
#include <array>
#include <cstdint>
#include <string>
#include "crypto_logger.hpp"

namespace crypto {

// Forward declarations of exceptions
class HashException : public std::runtime_error {
public:
    explicit HashException(const std::string& message) : std::runtime_error(message) {}
};

class InvalidHashInput : public HashException {
public:
    explicit InvalidHashInput(const std::string& message) : HashException(message) {}
};

class HashImpl {
public:
    // Core SHA-256 functionality
    std::vector<uint8_t> sha256(const std::vector<uint8_t>& message);
    std::vector<uint8_t> sha256(const std::string& message);  // Convenience overload for strings
    
    // HMAC-SHA256
    std::vector<uint8_t> hmacSha256(const std::vector<uint8_t>& message, 
                                   const std::vector<uint8_t>& key);

private:
    // SHA-256 constants
    static constexpr size_t BLOCK_SIZE = 64;  // 512 bits
    static constexpr size_t HASH_SIZE = 32;   // 256 bits
    static const std::array<uint32_t, 64> K;  // Declaration only

    // SHA-256 internal state
    std::array<uint32_t, 8> state = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // SHA-256 helper functions
    uint32_t ch(uint32_t x, uint32_t y, uint32_t z);
    uint32_t maj(uint32_t x, uint32_t y, uint32_t z);
    uint32_t rotr(uint32_t x, unsigned int n);
    uint32_t shr(uint32_t x, unsigned int n);
    uint32_t sigma0(uint32_t x);
    uint32_t sigma1(uint32_t x);
    uint32_t Sigma0(uint32_t x);
    uint32_t Sigma1(uint32_t x);

    // Core processing functions
    void processBlock(const uint8_t* block);
    std::vector<uint8_t> pad(const std::vector<uint8_t>& message);
    void resetState();

    // Utility functions
    static uint32_t bytesToUInt32(const uint8_t* bytes);
    static void uint32ToBytes(uint32_t value, uint8_t* bytes);
    static void validateInput(const std::vector<uint8_t>& input);
};

} // namespace crypto