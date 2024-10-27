// symmetric.hpp
#pragma once

#include "crypto_logger.hpp"
#include <vector>
#include <cstdint>
#include <array>
#include <memory>
#include <stdexcept>

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
        ~ModernSymmetricImpl() = default;

        // ECB Mode (not recommended for general use)
        std::vector<uint8_t> aesEncryptECB(const std::vector<uint8_t> &data,
                                           const std::vector<uint8_t> &key);
        std::vector<uint8_t> aesDecryptECB(const std::vector<uint8_t> &data,
                                           const std::vector<uint8_t> &key);

        // CBC Mode
        std::vector<uint8_t> aesEncryptCBC(const std::vector<uint8_t> &data,
                                           const std::vector<uint8_t> &key,
                                           const std::vector<uint8_t> &iv);
        std::vector<uint8_t> aesDecryptCBC(const std::vector<uint8_t> &data,
                                           const std::vector<uint8_t> &key,
                                           const std::vector<uint8_t> &iv);

        // CFB Mode
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
        static const size_t BlockSize = 16; // AES block size in bytes
        static const size_t Nb = 4;         // Number of columns in state
        AESKeyLength keyLength;
        size_t nr; // Number of rounds

        void validateKey(const std::vector<uint8_t> &key);
        void validateData(const std::vector<uint8_t> &data);
        void validateIV(const std::vector<uint8_t> &iv);

        void encryptBlock(const uint8_t in[BlockSize],
                          uint8_t out[BlockSize],
                          const std::vector<uint8_t> &roundKeys);
        void decryptBlock(const uint8_t in[BlockSize],
                          uint8_t out[BlockSize],
                          const std::vector<uint8_t> &roundKeys);

        // AES operations
        void addRoundKey(uint8_t state[4][4], const std::vector<uint8_t> &roundKeys, size_t round);
        void subBytes(uint8_t state[4][4]);
        void shiftRows(uint8_t state[4][4]);
        void mixColumns(uint8_t state[4][4]);
        void invSubBytes(uint8_t state[4][4]);
        void invShiftRows(uint8_t state[4][4]);
        void invMixColumns(uint8_t state[4][4]);

        // Helper functions
        uint8_t galoisMultiply(uint8_t a, uint8_t b) const;
        uint8_t xtime(uint8_t b) const;

        // Key scheduling
        std::vector<uint8_t> expandKey(const std::vector<uint8_t> &key);
        static size_t keyLengthToRounds(AESKeyLength length);

        // Padding methods
        std::vector<uint8_t> addPKCS7Padding(const std::vector<uint8_t> &data);
        std::vector<uint8_t> removePKCS7Padding(const std::vector<uint8_t> &data);

        // Additional validation
        void validatePadding(const std::vector<uint8_t> &paddedData);
        void validateNullData(const void *ptr, const std::string &context);
        void validateBlockAlignment(size_t size, const std::string &context);

        // Security helper methods
        static bool constantTimeMemEqual(const void *a, const void *b, size_t size);
        static void secureZero(void *ptr, size_t size);
    };

} // namespace crypto