// symmetric.hpp
#pragma once

#include "crypto_logger.hpp"
#include "aes_ni.hpp"
#include <vector>
#include <cstdint>
#include <array>
#include <memory>
#include <stdexcept>
#include <atomic>
#include <chrono>
#include <mutex>
#include <algorithm>
#include <sstream>

namespace crypto
{

    // Custom exceptions for better error handling
    class AESException : public std::runtime_error
    {
    public:
        explicit AESException(const std::string &message) : std::runtime_error(message) {}
    };

    class InvalidKeyLength : public AESException
    {
    public:
        explicit InvalidKeyLength(const std::string &message) : AESException(message) {}
    };

    class InvalidBlockSize : public AESException
    {
    public:
        explicit InvalidBlockSize(const std::string &message) : AESException(message) {}
    };

    // Declare lookup tables
    extern const std::array<std::array<uint8_t, 16>, 16> SBOX;
    extern const std::array<std::array<uint8_t, 16>, 16> INV_SBOX;
    extern const uint8_t RCON[10];
    extern const std::array<std::array<uint8_t, 256>, 256> GF_MUL_TABLE;

    enum class AESKeyLength
    {
        AES_128 = 16, // 128 bits
        AES_192 = 24, // 192 bits
        AES_256 = 32  // 256 bits
    };

    class ModernSymmetricImpl
    {
    public:
        explicit ModernSymmetricImpl(AESKeyLength keyLength = AESKeyLength::AES_128);
        ~ModernSymmetricImpl();

        // Public interface methods remain unchanged...
        std::vector<uint8_t> aesEncryptECB(const std::vector<uint8_t> &data,
                                           const std::vector<uint8_t> &key);
        std::vector<uint8_t> aesDecryptECB(const std::vector<uint8_t> &data,
                                           const std::vector<uint8_t> &key);
        std::vector<uint8_t> aesEncryptCBC(const std::vector<uint8_t> &data,
                                           const std::vector<uint8_t> &key,
                                           const std::vector<uint8_t> &iv);
        std::vector<uint8_t> aesDecryptCBC(const std::vector<uint8_t> &data,
                                           const std::vector<uint8_t> &key,
                                           const std::vector<uint8_t> &iv);
        std::vector<uint8_t> aesEncryptCFB(const std::vector<uint8_t> &data,
                                           const std::vector<uint8_t> &key,
                                           const std::vector<uint8_t> &iv);
        std::vector<uint8_t> aesDecryptCFB(const std::vector<uint8_t> &data,
                                           const std::vector<uint8_t> &key,
                                           const std::vector<uint8_t> &iv);
        std::vector<uint8_t> aesEncryptOFB(const std::vector<uint8_t> &data,
                                           const std::vector<uint8_t> &key,
                                           const std::vector<uint8_t> &iv);
        std::vector<uint8_t> aesDecryptOFB(const std::vector<uint8_t> &data,
                                           const std::vector<uint8_t> &key,
                                           const std::vector<uint8_t> &iv);

    private:
        // Constants
        static const size_t BlockSize = 16; // AES block size in bytes
        static const size_t Nb = 4;         // Number of columns in state

        // Security threshold constants
        static constexpr size_t MaxOperationsPerKey = 1ULL << 20; // 1 million operations
        static constexpr int MaxKeyAgeHours = 24;                 // Maximum key age
        static constexpr int MinBlockProcessingTime = 5;          // Minimum microseconds per block

        // Operation statistics structure (private to class)
        struct OperationStats
        {
            std::atomic<uint64_t> totalOperations{0};
            std::atomic<uint64_t> totalBytesProcessed{0};
            std::atomic<uint64_t> failedOperations{0};
            std::chrono::steady_clock::time_point lastFailure;
            std::mutex statsMutex;
        };

        // Instance variables
        AESKeyLength keyLength;
        size_t nr; // Number of rounds
        bool useHardwareAES;
        std::vector<uint8_t> expandedKey; // For software implementation

#ifdef USE_AES_NI
        std::vector<__m128i> aesniRoundKeys; // Only defined when AES-NI is available
#endif

        // Operation tracking
        std::atomic<uint64_t> encryptionCounter;
        std::chrono::steady_clock::time_point lastOperationTime;
        OperationStats operationStats;

        void prepareAESNI(const std::vector<uint8_t> &key);

        // Security monitoring methods
        void checkKeyRotation();
        bool hasAdequateEntropy(const std::vector<uint8_t> &data);
        void updateOperationStats(size_t bytesProcessed, bool success);

        // Rest of the private methods remain unchanged...
        void validateKey(const std::vector<uint8_t> &key);
        void validateData(const std::vector<uint8_t> &data);
        void validateIV(const std::vector<uint8_t> &iv);
        void validateBlockAlignment(size_t size, const std::string &context);
        static void validateNullData(const void *ptr, const std::string &context);

        // Block operations with hardware/software dispatch
        void encryptBlock(const uint8_t in[BlockSize],
                          uint8_t out[BlockSize],
                          const std::vector<uint8_t> &roundKeys);

        void decryptBlock(const uint8_t in[BlockSize],
                          uint8_t out[BlockSize],
                          const std::vector<uint8_t> &roundKeys);

        // Software implementation of block operations
        void encryptBlockSoftware(const uint8_t in[BlockSize],
                                  uint8_t out[BlockSize],
                                  const std::vector<uint8_t> &roundKeys);

        void decryptBlockSoftware(const uint8_t in[BlockSize],
                                  uint8_t out[BlockSize],
                                  const std::vector<uint8_t> &roundKeys);

        // AES operations
        void subBytes(uint8_t state[4][4]);
        void invSubBytes(uint8_t state[4][4]);
        void shiftRows(uint8_t state[4][4]);
        void invShiftRows(uint8_t state[4][4]);
        void mixColumns(uint8_t state[4][4]);
        void invMixColumns(uint8_t state[4][4]);
        void addRoundKey(uint8_t state[4][4],
                         const std::vector<uint8_t> &roundKey,
                         size_t round);

        // Helper functions
        uint8_t galoisMultiply(uint8_t a, uint8_t b) const;
        uint8_t xtime(uint8_t b) const;
        static bool constantTimeMemEqual(const void *a, const void *b, size_t size);
        static void secureZero(void *ptr, size_t size);

        // Key operations
        void prepareKey(const std::vector<uint8_t> &key);
        std::vector<uint8_t> expandKey(const std::vector<uint8_t> &key);
        static size_t keyLengthToRounds(AESKeyLength length);

        // Padding operations
        std::vector<uint8_t> addPKCS7Padding(const std::vector<uint8_t> &data);
        std::vector<uint8_t> removePKCS7Padding(const std::vector<uint8_t> &data);
        void validatePadding(const std::vector<uint8_t> &paddedData);
        static bool verifyPaddingConstantTime(const std::vector<uint8_t> &data,
                                              uint8_t paddingLength)
        {
            if (paddingLength == 0 || paddingLength > BlockSize ||
                paddingLength > data.size())
            {
                return false;
            }

            uint8_t result = 0;
            for (size_t i = data.size() - paddingLength; i < data.size(); i++)
            {
                result |= data[i] ^ paddingLength;
            }
            return result == 0;
        }

        static uint8_t constantTimeSelect(uint8_t mask, uint8_t a, uint8_t b)
        {
            return (mask & (a ^ b)) ^ b;
        }
    };

} // namespace crypto