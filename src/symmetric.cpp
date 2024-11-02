// symmetric.cpp
#include "symmetric.hpp"
#include <cstring>
#include <limits>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#include <wmmintrin.h>
#define USE_AES_NI
#endif

namespace crypto
{

    const size_t ModernSymmetricImpl::BlockSize;

    const uint8_t RCON[10] = {
        0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1B, 0x36};

    // Initialize lookup tables
    const std::array<std::array<uint8_t, 16>, 16> SBOX = {{{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
                                                           {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
                                                           {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
                                                           {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
                                                           {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
                                                           {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
                                                           {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
                                                           {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
                                                           {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
                                                           {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
                                                           {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
                                                           {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
                                                           {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
                                                           {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
                                                           {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
                                                           {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}}};

    const std::array<std::array<uint8_t, 16>, 16> INV_SBOX = {{{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
                                                               {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
                                                               {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
                                                               {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
                                                               {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
                                                               {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
                                                               {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
                                                               {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
                                                               {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
                                                               {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
                                                               {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
                                                               {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
                                                               {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
                                                               {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
                                                               {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
                                                               {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}}};

    ModernSymmetricImpl::ModernSymmetricImpl(AESKeyLength keyLength)
        : keyLength(keyLength),
          nr(keyLengthToRounds(keyLength)),
          useHardwareAES(false), // Initialize to false first
          encryptionCounter(0),
          lastOperationTime(std::chrono::steady_clock::now())
    {
        CryptoLogger::info("Initializing AES implementation");

        // Validate parameters
        if (nr == 0 || nr > 14)
        {
            throw InvalidKeyLength("Invalid number of rounds: " + std::to_string(nr));
        }

#ifdef USE_AES_NI
        // Check for hardware support
        useHardwareAES = AESNIImpl::available();
        if (useHardwareAES)
        {
            CryptoLogger::info("Using AES-NI hardware acceleration");
        }
        else
        {
            CryptoLogger::info("Hardware acceleration not available, using software implementation");
        }
#else
        CryptoLogger::info("Using software implementation (AES-NI not compiled in)");
#endif

        // Initialize lookup tables and state
        expandedKey.reserve(4 * Nb * (nr + 1));
#ifdef USE_AES_NI
        if (useHardwareAES)
        {
            aesniRoundKeys.reserve(nr + 1);
        }
#endif
    }

    ModernSymmetricImpl::~ModernSymmetricImpl()
    {
        // Securely clear sensitive data
        if (!expandedKey.empty())
        {
            secureZero(expandedKey.data(), expandedKey.size());
        }
#ifdef USE_AES_NI
        if (!aesniRoundKeys.empty())
        {
            secureZero(aesniRoundKeys.data(), aesniRoundKeys.size() * sizeof(__m128i));
        }
#endif
    }

    uint8_t ModernSymmetricImpl::xtime(uint8_t b) const
    {
        uint8_t result = (b << 1) ^ ((b & 0x80) ? 0x1B : 0x00);

        if (CryptoLogger::should_log(LogLevel::TRACE))
        {
            std::stringstream ss;
            ss << "xtime(0x" << std::hex << static_cast<int>(b)
               << ") = 0x" << static_cast<int>(result);
            CryptoLogger::trace(ss.str());
        }

        return result;
    }

    uint8_t ModernSymmetricImpl::galoisMultiply(uint8_t a, uint8_t b) const
    {
        CryptoLogger::trace("Galois Field multiplication: " +
                            std::to_string(static_cast<int>(a)) + " * " +
                            std::to_string(static_cast<int>(b)));

        uint8_t p = 0;
        uint8_t hi_bit_set;
        for (int i = 0; i < 8; i++)
        {
            if (b & 1)
            {
                p ^= a;
                CryptoLogger::trace("  Step " + std::to_string(i) + ": p ^= a -> " +
                                    std::to_string(static_cast<int>(p)));
            }
            hi_bit_set = (a & 0x80);
            a <<= 1;
            if (hi_bit_set)
            {
                a ^= 0x1b; // AES irreducible polynomial
                CryptoLogger::trace("  Step " + std::to_string(i) + ": Reduction with 0x1B");
            }
            b >>= 1;
        }

        CryptoLogger::trace("Galois multiplication result: " + std::to_string(static_cast<int>(p)));
        return p;
    }

    void ModernSymmetricImpl::subBytes(uint8_t state[4][4])
    {
        CryptoLogger::trace("Applying SubBytes transformation");
        CryptoLogger::log_state_array(state, "Before SubBytes");

        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                uint8_t val = state[i][j];
                state[i][j] = SBOX[val >> 4][val & 0x0F];
            }
        }

        CryptoLogger::log_state_array(state, "After SubBytes");
    }

    void ModernSymmetricImpl::invSubBytes(uint8_t state[4][4])
    {
        CryptoLogger::trace("Applying Inverse SubBytes transformation");
        CryptoLogger::log_state_array(state, "Before InvSubBytes");

        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                uint8_t val = state[i][j];
                state[i][j] = INV_SBOX[val >> 4][val & 0x0F];
            }
        }

        CryptoLogger::log_state_array(state, "After InvSubBytes");
    }

    void ModernSymmetricImpl::shiftRows(uint8_t state[4][4])
    {
        CryptoLogger::trace("Applying ShiftRows transformation");
        CryptoLogger::log_state_array(state, "Before ShiftRows");

        uint8_t temp;

        // Row 1: shift left by 1
        temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp;

        // Row 2: shift left by 2
        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;

        // Row 3: shift left by 3
        temp = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = temp;

        CryptoLogger::log_state_array(state, "After ShiftRows");
    }

    void ModernSymmetricImpl::invShiftRows(uint8_t state[4][4])
    {
        CryptoLogger::trace("Applying Inverse ShiftRows transformation");
        CryptoLogger::log_state_array(state, "Before InvShiftRows");

        uint8_t temp;

        // Row 1: shift right by 1
        temp = state[1][3];
        state[1][3] = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = state[1][0];
        state[1][0] = temp;

        // Row 2: shift right by 2
        std::swap(state[2][0], state[2][2]);
        std::swap(state[2][1], state[2][3]);

        // Row 3: shift right by 3
        temp = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = temp;

        CryptoLogger::log_state_array(state, "After InvShiftRows");
    }

    void ModernSymmetricImpl::mixColumns(uint8_t state[4][4])
    {
        CryptoLogger::trace("Applying MixColumns transformation");
        CryptoLogger::log_state_array(state, "Before MixColumns");

        uint8_t temp[4][4];

        for (int col = 0; col < 4; col++)
        {
            temp[0][col] = galoisMultiply(0x02, state[0][col]) ^
                           galoisMultiply(0x03, state[1][col]) ^
                           state[2][col] ^
                           state[3][col];

            temp[1][col] = state[0][col] ^
                           galoisMultiply(0x02, state[1][col]) ^
                           galoisMultiply(0x03, state[2][col]) ^
                           state[3][col];

            temp[2][col] = state[0][col] ^
                           state[1][col] ^
                           galoisMultiply(0x02, state[2][col]) ^
                           galoisMultiply(0x03, state[3][col]);

            temp[3][col] = galoisMultiply(0x03, state[0][col]) ^
                           state[1][col] ^
                           state[2][col] ^
                           galoisMultiply(0x02, state[3][col]);

            if (CryptoLogger::should_log(LogLevel::TRACE))
            {
                CryptoLogger::trace("Column " + std::to_string(col) + " transformed");
            }
        }

        std::memcpy(state, temp, 16);
        CryptoLogger::log_state_array(state, "After MixColumns");
    }

    void ModernSymmetricImpl::invMixColumns(uint8_t state[4][4])
    {
        CryptoLogger::trace("Applying Inverse MixColumns transformation");
        CryptoLogger::log_state_array(state, "Before InvMixColumns");

        uint8_t temp[4][4];

        for (int col = 0; col < 4; col++)
        {
            temp[0][col] = galoisMultiply(0x0e, state[0][col]) ^
                           galoisMultiply(0x0b, state[1][col]) ^
                           galoisMultiply(0x0d, state[2][col]) ^
                           galoisMultiply(0x09, state[3][col]);

            temp[1][col] = galoisMultiply(0x09, state[0][col]) ^
                           galoisMultiply(0x0e, state[1][col]) ^
                           galoisMultiply(0x0b, state[2][col]) ^
                           galoisMultiply(0x0d, state[3][col]);

            temp[2][col] = galoisMultiply(0x0d, state[0][col]) ^
                           galoisMultiply(0x09, state[1][col]) ^
                           galoisMultiply(0x0e, state[2][col]) ^
                           galoisMultiply(0x0b, state[3][col]);

            temp[3][col] = galoisMultiply(0x0b, state[0][col]) ^
                           galoisMultiply(0x0d, state[1][col]) ^
                           galoisMultiply(0x09, state[2][col]) ^
                           galoisMultiply(0x0e, state[3][col]);

            if (CryptoLogger::should_log(LogLevel::TRACE))
            {
                CryptoLogger::trace("Column " + std::to_string(col) + " inverse transformed");
            }
        }

        std::memcpy(state, temp, 16);
        CryptoLogger::log_state_array(state, "After InvMixColumns");
    }

    void ModernSymmetricImpl::prepareKey(const std::vector<uint8_t> &key)
    {
        validateKey(key);

        try
        {
            if (useHardwareAES)
            {
                // First try hardware acceleration
                prepareAESNI(key);
            }
        }
        catch (const std::exception &e)
        {
            CryptoLogger::warning("Hardware acceleration failed, falling back to software: " +
                                  std::string(e.what()));
            useHardwareAES = false;
        }

        // Always prepare software implementation keys as fallback
        expandedKey = expandKey(key);
    }

    std::vector<uint8_t> ModernSymmetricImpl::expandKey(const std::vector<uint8_t> &key)
    {
        const size_t Nk = static_cast<size_t>(keyLength);
        const size_t expandedKeySize = 4 * Nb * (nr + 1);

        CryptoLogger::debug("Starting key expansion: input size=" +
                            std::to_string(key.size()) +
                            " bytes, output size=" +
                            std::to_string(expandedKeySize) + " bytes");

        std::vector<uint8_t> expandedKey(expandedKeySize);
        std::memcpy(expandedKey.data(), key.data(), key.size());

        alignas(16) uint8_t temp[4];
        size_t i = Nk;

        while (i < expandedKeySize / 4)
        {
            std::memcpy(temp, &expandedKey[(i - 1) * 4], 4);

            if (i % Nk == 0)
            {
                CryptoLogger::trace("Key schedule round " + std::to_string(i / Nk));

                // Rotate word and log
                uint8_t tempByte = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = tempByte;

                CryptoLogger::log_bytes(temp, 4, "After RotWord");

                // S-box substitution
                for (size_t j = 0; j < 4; j++)
                {
                    temp[j] = SBOX[temp[j] >> 4][temp[j] & 0x0F];
                }
                CryptoLogger::log_bytes(temp, 4, "After SubWord");

                temp[0] ^= RCON[i / Nk - 1];
                CryptoLogger::log_bytes(temp, 4, "After RCON");
            }
            else if (Nk > 6 && i % Nk == 4)
            {
                CryptoLogger::trace("AES-256 extra substitution at word " + std::to_string(i));
                for (size_t j = 0; j < 4; j++)
                {
                    temp[j] = SBOX[temp[j] >> 4][temp[j] & 0x0F];
                }
                CryptoLogger::log_bytes(temp, 4, "After SubWord");
            }

            // XOR with previous key material
            for (size_t j = 0; j < 4; j++)
            {
                expandedKey[i * 4 + j] = expandedKey[(i - Nk) * 4 + j] ^ temp[j];
            }

            if (CryptoLogger::should_log(LogLevel::TRACE))
            {
                CryptoLogger::log_bytes(&expandedKey[i * 4], 4,
                                        "Generated word " + std::to_string(i));
            }

            i++;
        }

        if (CryptoLogger::get_debug_mode())
        {
            CryptoLogger::debug("Key expansion completed successfully");
            CryptoLogger::log_bytes(expandedKey.data(), expandedKey.size(),
                                    "Final expanded key");
        }

        return expandedKey;
    }

    void ModernSymmetricImpl::addRoundKey(uint8_t state[4][4],
                                          const std::vector<uint8_t> &roundKey,
                                          size_t round)
    {
        CryptoLogger::trace("Adding round key " + std::to_string(round));
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                // Column-major format
                state[j][i] ^= roundKey[round * 16 + i * 4 + j];
            }
        }
    }

    void ModernSymmetricImpl::encryptBlock(const uint8_t in[BlockSize],
                                           uint8_t out[BlockSize],
                                           const std::vector<uint8_t> &roundKeys)
    {
#ifdef USE_AES_NI
        if (useHardwareAES)
        {
            try
            {
                if (aesniRoundKeys.empty())
                {
                    throw std::runtime_error("AES-NI round keys not prepared");
                }
                AESNIImpl::encryptBlock(in, out, aesniRoundKeys.data(), nr);
                return;
            }
            catch (const std::exception &e)
            {
                CryptoLogger::warning("Hardware encryption failed, falling back to software: " +
                                      std::string(e.what()));
                useHardwareAES = false;
            }
        }
#endif

        CryptoLogger::debug("Using software implementation for encryption");
        encryptBlockSoftware(in, out, roundKeys);
    }

    void ModernSymmetricImpl::decryptBlock(const uint8_t in[BlockSize],
                                           uint8_t out[BlockSize],
                                           const std::vector<uint8_t> &roundKeys)
    {
#ifdef USE_AES_NI
        if (useHardwareAES)
        {
            try
            {
                if (aesniRoundKeys.empty())
                {
                    throw std::runtime_error("AES-NI round keys not prepared");
                }
                AESNIImpl::decryptBlock(in, out, aesniRoundKeys.data(), nr);
                return;
            }
            catch (const std::exception &e)
            {
                CryptoLogger::warning("Hardware decryption failed, falling back to software: " +
                                      std::string(e.what()));
                useHardwareAES = false;
            }
        }
#endif

        CryptoLogger::debug("Using software implementation for decryption");
        decryptBlockSoftware(in, out, roundKeys);
    }

    void ModernSymmetricImpl::encryptBlockSoftware(
        const uint8_t in[BlockSize],
        uint8_t out[BlockSize],
        const std::vector<uint8_t> &roundKeys)
    {
        CryptoLogger::trace("Starting block encryption");

        // Use aligned state array
        alignas(16) uint8_t state[4][4];

        // Load input into state array in column-major format
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                state[j][i] = in[i * 4 + j];
            }
        }
        CryptoLogger::log_state_array(state, "Initial state");

        // Initial round key addition
        this->addRoundKey(state, roundKeys, 0);
        CryptoLogger::log_state_array(state, "After initial AddRoundKey");

        // Main rounds
        for (size_t round = 1; round < nr; round++)
        {
            CryptoLogger::trace("Starting encryption round " + std::to_string(round));

            this->subBytes(state);
            CryptoLogger::log_state_array(state, "After SubBytes");

            this->shiftRows(state);
            CryptoLogger::log_state_array(state, "After ShiftRows");

            this->mixColumns(state);
            CryptoLogger::log_state_array(state, "After MixColumns");

            this->addRoundKey(state, roundKeys, round);
            CryptoLogger::log_state_array(state, "After AddRoundKey");
        }

        // Final round (no mixColumns)
        CryptoLogger::trace("Starting final round");

        this->subBytes(state);
        CryptoLogger::log_state_array(state, "After final SubBytes");

        this->shiftRows(state);
        CryptoLogger::log_state_array(state, "After final ShiftRows");

        this->addRoundKey(state, roundKeys, nr);
        CryptoLogger::log_state_array(state, "After final AddRoundKey");

        // Store result in column-major format
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                out[i * 4 + j] = state[j][i];
            }
        }

        CryptoLogger::trace("Block encryption completed");
    }

    void ModernSymmetricImpl::decryptBlockSoftware(
        const uint8_t in[BlockSize],
        uint8_t out[BlockSize],
        const std::vector<uint8_t> &roundKeys)
    {
        CryptoLogger::trace("Starting block decryption");

        // Use aligned state array
        alignas(16) uint8_t state[4][4];

        // Load input into state array in column-major format
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                state[j][i] = in[i * 4 + j];
            }
        }
        CryptoLogger::log_state_array(state, "Initial state");

        // Initial round
        this->addRoundKey(state, roundKeys, nr);
        CryptoLogger::log_state_array(state, "After initial AddRoundKey");

        // Main rounds
        for (size_t round = nr - 1; round > 0; --round)
        {
            CryptoLogger::trace("Starting decryption round " + std::to_string(round));

            this->invShiftRows(state);
            CryptoLogger::log_state_array(state, "After InvShiftRows");

            this->invSubBytes(state);
            CryptoLogger::log_state_array(state, "After InvSubBytes");

            this->addRoundKey(state, roundKeys, round);
            CryptoLogger::log_state_array(state, "After AddRoundKey");

            this->invMixColumns(state);
            CryptoLogger::log_state_array(state, "After InvMixColumns");
        }

        // Final round
        this->invShiftRows(state);
        CryptoLogger::log_state_array(state, "After final InvShiftRows");

        this->invSubBytes(state);
        CryptoLogger::log_state_array(state, "After final InvSubBytes");

        this->addRoundKey(state, roundKeys, 0);
        CryptoLogger::log_state_array(state, "After final AddRoundKey");

        // Store result in column-major format
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                out[i * 4 + j] = state[j][i];
            }
        }

        CryptoLogger::trace("Block decryption completed");
    }

    std::vector<uint8_t> ModernSymmetricImpl::addPKCS7Padding(const std::vector<uint8_t> &data)
    {
        // Calculate padding length
        const uint8_t paddingLength = BlockSize - (data.size() % BlockSize);
        const size_t paddedSize = data.size() + paddingLength;

        CryptoLogger::debug("Original data size: " + std::to_string(data.size()));
        CryptoLogger::debug("Padding length: " + std::to_string(static_cast<int>(paddingLength)));

        // Create padded data
        std::vector<uint8_t> paddedData;
        paddedData.reserve(paddedSize);
        paddedData.insert(paddedData.end(), data.begin(), data.end());
        paddedData.insert(paddedData.end(), paddingLength, paddingLength);

        // Verify padding
        if (paddedData.size() != paddedSize || paddedData.size() % BlockSize != 0)
        {
            throw AESException("Padding error: incorrect final size");
        }

        return paddedData;
    }

    std::vector<uint8_t> ModernSymmetricImpl::removePKCS7Padding(const std::vector<uint8_t> &data)
    {
        // Basic validation
        if (data.size() < BlockSize || data.size() % BlockSize != 0)
        {
            throw AESException("Invalid padded data size");
        }

        // Get padding length from last byte
        uint8_t paddingLength = data.back();

        // Validate padding length
        if (paddingLength == 0 || paddingLength > BlockSize || paddingLength > data.size())
        {
            throw AESException("Invalid padding length");
        }

        // Verify all padding bytes in constant time
        uint8_t validationMask = 0;
        const size_t messageLength = data.size() - paddingLength;

        // Check for potential integer underflow
        if (messageLength > data.size())
        {
            throw AESException("Padding length would cause underflow");
        }

        // Check all padding bytes in constant time
        for (size_t i = messageLength; i < data.size(); i++)
        {
            validationMask |= data[i] ^ paddingLength;
        }

        // If any padding byte is incorrect, validationMask will be non-zero
        if (validationMask != 0)
        {
            throw AESException("Invalid padding bytes");
        }

        // Return unpadded data
        return std::vector<uint8_t>(data.begin(), data.begin() + messageLength);
    }

    void ModernSymmetricImpl::validatePadding(const std::vector<uint8_t> &paddedData)
    {
        if (paddedData.empty())
        {
            throw InvalidBlockSize("Padded data is empty");
        }
        validateBlockAlignment(paddedData.size(), "Padded data");

        uint8_t paddingLength = paddedData.back();
        if (paddingLength == 0 || paddingLength > BlockSize || paddingLength > paddedData.size())
        {
            throw AESException("Invalid padding length");
        }
    }

    std::vector<uint8_t> ModernSymmetricImpl::aesEncryptECB(
        const std::vector<uint8_t> &data,
        const std::vector<uint8_t> &key)
    {
        try
        {
            validateKey(key);
            if (data.empty())
            {
                throw InvalidBlockSize("Input data is empty");
            }

            // Prepare keys before encryption
            prepareKey(key);

            CryptoLogger::info("Starting ECB encryption operation");
            CryptoLogger::warning("ECB mode is not recommended for secure operations");

            std::vector<uint8_t> paddedData = this->addPKCS7Padding(data);
            std::vector<uint8_t> output(paddedData.size());

            for (size_t i = 0; i < paddedData.size(); i += BlockSize)
            {
                this->encryptBlock(paddedData.data() + i, output.data() + i, expandedKey);
            }

            CryptoLogger::info("ECB encryption completed successfully");
            return output;
        }
        catch (const std::exception &e)
        {
            CryptoLogger::error("ECB encryption failed");
            CryptoLogger::log_exception(e, "ECB encryption");
            throw;
        }
    }

    std::vector<uint8_t> ModernSymmetricImpl::aesEncryptCBC(
        const std::vector<uint8_t> &data,
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &iv)
    {
        try
        {
            validateKey(key);
            validateIV(iv);
            validateData(data);

            // Prepare keys - this sets up both hardware and software keys
            prepareKey(key);

            const std::vector<uint8_t> paddedData = addPKCS7Padding(data);
            std::vector<uint8_t> output(paddedData.size());

            // Use aligned buffers for better SIMD performance
            auto blockBuffer = AESNIImpl::alignedAlloc(BlockSize);
            auto prevBlock = AESNIImpl::alignedAlloc(BlockSize);

            std::memcpy(prevBlock.get(), iv.data(), BlockSize);

            // Debug the padded data
            CryptoLogger::debug("Padded data before encryption:");
            for (size_t i = 0; i < paddedData.size(); i += BlockSize)
            {
                std::stringstream ss;
                ss << "Block " << (i / BlockSize) << ": ";
                for (size_t j = 0; j < BlockSize; j++)
                {
                    ss << std::hex << std::setw(2) << std::setfill('0')
                       << static_cast<int>(paddedData[i + j]) << " ";
                }
                CryptoLogger::debug(ss.str());
            }

            for (size_t i = 0; i < paddedData.size(); i += BlockSize)
            {
                // XOR with previous block
                for (size_t j = 0; j < BlockSize; j++)
                {
                    blockBuffer[j] = paddedData[i + j] ^ prevBlock[j];
                }

                encryptBlock(blockBuffer.get(), output.data() + i, expandedKey);
                std::memcpy(prevBlock.get(), output.data() + i, BlockSize);
            }

            return output;
        }
        catch (const std::exception &e)
        {
            CryptoLogger::error("CBC encryption failed: " + std::string(e.what()));
            throw;
        }
    }

    std::vector<uint8_t> ModernSymmetricImpl::aesEncryptCFB(
        const std::vector<uint8_t> &data,
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &iv)
    {
        try
        {
            validateKey(key);
            validateIV(iv);
            if (data.empty())
            {
                throw InvalidBlockSize("Input data is empty");
            }

            // Prepare keys before encryption
            prepareKey(key);

            CryptoLogger::debug("Starting CFB encryption");

            std::vector<uint8_t> output(data.size());
            std::vector<uint8_t> previousBlock = iv;
            std::vector<uint8_t> encryptedBlock(BlockSize);

            size_t processedBytes = 0;
            while (processedBytes < data.size())
            {
                this->encryptBlock(previousBlock.data(), encryptedBlock.data(), expandedKey);

                size_t bytesToProcess = std::min(BlockSize, data.size() - processedBytes);
                for (size_t j = 0; j < bytesToProcess; j++)
                {
                    output[processedBytes + j] = data[processedBytes + j] ^ encryptedBlock[j];
                }

                previousBlock = std::vector<uint8_t>(output.begin() + processedBytes,
                                                     output.begin() + processedBytes + bytesToProcess);
                processedBytes += bytesToProcess;
            }

            return output;
        }
        catch (const std::exception &e)
        {
            CryptoLogger::error("CFB encryption failed");
            CryptoLogger::log_exception(e, "CFB encryption");
            throw;
        }
    }

    std::vector<uint8_t> ModernSymmetricImpl::aesEncryptOFB(
        const std::vector<uint8_t> &data,
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &iv)
    {
        try
        {
            validateKey(key);
            validateIV(iv);
            if (data.empty())
            {
                throw InvalidBlockSize("Input data is empty");
            }

            // Prepare keys before encryption
            prepareKey(key);

            CryptoLogger::debug("Starting OFB encryption");

            std::vector<uint8_t> output(data.size());
            std::vector<uint8_t> keystream = iv;

            size_t processedBytes = 0;
            while (processedBytes < data.size())
            {
                this->encryptBlock(keystream.data(), keystream.data(), expandedKey);

                size_t bytesToProcess = std::min(BlockSize, data.size() - processedBytes);
                for (size_t j = 0; j < bytesToProcess; j++)
                {
                    output[processedBytes + j] = data[processedBytes + j] ^ keystream[j];
                }

                processedBytes += bytesToProcess;
            }

            return output;
        }
        catch (const std::exception &e)
        {
            CryptoLogger::error("OFB encryption failed");
            CryptoLogger::log_exception(e, "OFB encryption");
            throw;
        }
    }

    std::vector<uint8_t> ModernSymmetricImpl::aesDecryptECB(
        const std::vector<uint8_t> &data,
        const std::vector<uint8_t> &key)
    {
        try
        {
            validateKey(key);
            validateBlockAlignment(data.size(), "Input data");

            // Prepare keys before decryption
            prepareKey(key);

            CryptoLogger::debug("Starting ECB decryption");
            std::vector<uint8_t> output(data.size());

            for (size_t i = 0; i < data.size(); i += BlockSize)
            {
                this->decryptBlock(data.data() + i, output.data() + i, expandedKey);
            }

            std::vector<uint8_t> unpaddedData = this->removePKCS7Padding(output);
            CryptoLogger::debug("ECB decryption completed successfully");
            return unpaddedData;
        }
        catch (const std::exception &e)
        {
            CryptoLogger::error("ECB decryption failed");
            CryptoLogger::log_exception(e, "ECB decryption");
            throw;
        }
    }

    std::vector<uint8_t> ModernSymmetricImpl::aesDecryptCBC(
        const std::vector<uint8_t> &data,
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &iv)
    {
        try
        {
            validateKey(key);
            validateData(data);
            validateIV(iv);

            // Prepare keys before decryption
            prepareKey(key);

            std::vector<uint8_t> output(data.size());

            auto decryptBuffer = AESNIImpl::alignedAlloc(BlockSize);
            auto prevBlock = AESNIImpl::alignedAlloc(BlockSize);

            std::memcpy(prevBlock.get(), iv.data(), BlockSize);

            for (size_t i = 0; i < data.size(); i += BlockSize)
            {
                decryptBlock(data.data() + i, decryptBuffer.get(), expandedKey);

                for (size_t j = 0; j < BlockSize; j++)
                {
                    output[i + j] = decryptBuffer[j] ^ prevBlock[j];
                }

                std::memcpy(prevBlock.get(), data.data() + i, BlockSize);
            }

            if (CryptoLogger::get_debug_mode())
            {
                CryptoLogger::debug("Decrypted data before unpadding:");
                for (size_t i = 0; i < output.size(); i += BlockSize)
                {
                    std::stringstream ss;
                    ss << "Block " << (i / BlockSize) << ": ";
                    for (size_t j = 0; j < BlockSize; j++)
                    {
                        ss << std::hex << std::setw(2) << std::setfill('0')
                           << static_cast<int>(output[i + j]) << " ";
                    }
                    CryptoLogger::debug(ss.str());
                }
            }

            return removePKCS7Padding(output);
        }
        catch (const std::exception &e)
        {
            CryptoLogger::error("CBC decryption failed: " + std::string(e.what()));
            throw;
        }
    }

    std::vector<uint8_t> ModernSymmetricImpl::aesDecryptCFB(
        const std::vector<uint8_t> &data,
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &iv)
    {
        try
        {
            validateKey(key);
            validateIV(iv);
            if (data.empty())
            {
                throw InvalidBlockSize("Input data is empty");
            }

            // Prepare keys before decryption
            prepareKey(key);

            CryptoLogger::debug("Starting CFB decryption");

            std::vector<uint8_t> output(data.size());
            std::vector<uint8_t> previousBlock = iv;
            std::vector<uint8_t> encryptedBlock(BlockSize);

            size_t processedBytes = 0;
            while (processedBytes < data.size())
            {
                this->encryptBlock(previousBlock.data(), encryptedBlock.data(), expandedKey);

                size_t bytesToProcess = std::min(BlockSize, data.size() - processedBytes);
                for (size_t j = 0; j < bytesToProcess; j++)
                {
                    output[processedBytes + j] = data[processedBytes + j] ^ encryptedBlock[j];
                }

                previousBlock.assign(data.begin() + processedBytes,
                                     data.begin() + processedBytes + bytesToProcess);
                processedBytes += bytesToProcess;
            }

            return output;
        }
        catch (const std::exception &e)
        {
            CryptoLogger::error("CFB decryption failed");
            CryptoLogger::log_exception(e, "CFB decryption");
            throw;
        }
    }

    // OFB decryption is identical to encryption
    std::vector<uint8_t> ModernSymmetricImpl::aesDecryptOFB(
        const std::vector<uint8_t> &data,
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &iv)
    {
        return this->aesEncryptOFB(data, key, iv); // OFB mode is symmetric
    }

    void ModernSymmetricImpl::validateKey(const std::vector<uint8_t> &key)
    {
        CryptoLogger::debug("Validating key of length " +
                            std::to_string(key.size()) + " bytes");

        if (key.size() != static_cast<size_t>(keyLength))
        {
            throw InvalidKeyLength("Invalid key length: " +
                                   std::to_string(key.size()) + " bytes");
        }

        if (!hasAdequateEntropy(key))
        {
            CryptoLogger::warning("Key has low entropy - consider regenerating");
        }

        // Check for weak keys (all zeros, all ones, repeated patterns)
        bool isWeak = false;
        if (std::all_of(key.begin(), key.end(),
                        [](uint8_t b)
                        { return b == 0x00; }))
        {
            isWeak = true;
        }
        if (std::all_of(key.begin(), key.end(),
                        [](uint8_t b)
                        { return b == 0xFF; }))
        {
            isWeak = true;
        }

        if (isWeak)
        {
            throw InvalidKeyLength("Weak key detected");
        }
    }

    // Add operation monitoring
    void ModernSymmetricImpl::updateOperationStats(size_t bytesProcessed,
                                                   bool success)
    {
        std::lock_guard<std::mutex> lock(operationStats.statsMutex);
        operationStats.totalOperations++;
        operationStats.totalBytesProcessed += bytesProcessed;

        if (!success)
        {
            operationStats.failedOperations++;
            operationStats.lastFailure = std::chrono::steady_clock::now();
        }
    }

    void ModernSymmetricImpl::validateIV(const std::vector<uint8_t> &iv)
    {
        CryptoLogger::debug("Validating IV of length " + std::to_string(iv.size()) + " bytes");

        if (iv.size() != BlockSize)
        {
            CryptoLogger::error("Invalid IV size: " + std::to_string(iv.size()) +
                                " bytes (expected " + std::to_string(BlockSize) + " bytes)");
            throw InvalidBlockSize("IV must be exactly " + std::to_string(BlockSize) + " bytes");
        }

        // Check for zero IV
        bool isZeroIV = true;
        for (const auto &byte : iv)
        {
            if (byte != 0)
            {
                isZeroIV = false;
                break;
            }
        }

        if (isZeroIV)
        {
            CryptoLogger::warning("IV consists of all zero bytes - this is not cryptographically secure");
        }
    }

    void ModernSymmetricImpl::validateBlockAlignment(size_t size, const std::string &context)
    {
        std::stringstream ss;
        ss << "Validating block alignment for " << context
           << " (size=" << size << " bytes)";
        CryptoLogger::debug(ss.str());

        if (size == 0)
        {
            ss.str("");
            ss << context << " is empty";
            CryptoLogger::error(ss.str());
            throw InvalidBlockSize(ss.str());
        }

        if (size % BlockSize != 0)
        {
            ss.str("");
            ss << context << " size (" << size
               << ") must be a multiple of " << BlockSize << " bytes";
            CryptoLogger::error(ss.str());
            throw InvalidBlockSize(ss.str());
        }

        CryptoLogger::debug("Block alignment validation successful");
    }

    // Constant-time comparison to prevent timing attacks
    bool ModernSymmetricImpl::constantTimeMemEqual(const void *a, const void *b, size_t size)
    {
        if (CryptoLogger::should_log(LogLevel::TRACE))
        {
            CryptoLogger::trace("Performing constant-time memory comparison of " +
                                std::to_string(size) + " bytes");
        }

        validateNullData(a, "first comparison buffer");
        validateNullData(b, "second comparison buffer");

        const volatile unsigned char *aa = static_cast<const volatile unsigned char *>(a);
        const volatile unsigned char *bb = static_cast<const volatile unsigned char *>(b);
        volatile unsigned char result = 0;

        for (size_t i = 0; i < size; ++i)
        {
            result |= aa[i] ^ bb[i];
        }

        bool equal = (result == 0);
        if (CryptoLogger::should_log(LogLevel::TRACE))
        {
            CryptoLogger::trace("Memory comparison result: " +
                                std::string(equal ? "equal" : "not equal"));
        }

        return equal;
    }

    // Secure memory wiping
    void ModernSymmetricImpl::secureZero(void *ptr, size_t size)
    {
        if (CryptoLogger::should_log(LogLevel::DEBUG))
        {
            CryptoLogger::debug("Securely zeroing " + std::to_string(size) + " bytes");
        }

        validateNullData(ptr, "memory to zero");

        volatile unsigned char *p = static_cast<volatile unsigned char *>(ptr);
        while (size--)
        {
            *p++ = 0;
        }

        if (CryptoLogger::should_log(LogLevel::DEBUG))
        {
            CryptoLogger::debug("Secure zeroing completed");
        }
    }

    size_t ModernSymmetricImpl::keyLengthToRounds(AESKeyLength length)
    {
        switch (length)
        {
        case AESKeyLength::AES_128:
            return 10;
        case AESKeyLength::AES_192:
            return 12;
        case AESKeyLength::AES_256:
            return 14;
        default:
            throw InvalidKeyLength("Invalid key length");
        }
    }

    void ModernSymmetricImpl::validateNullData(const void *ptr, const std::string &context)
    {
        if (ptr == nullptr)
        {
            std::string message = "Null pointer provided for " + context;
            CryptoLogger::error(message);
            throw AESException(message);
        }
    }

    void ModernSymmetricImpl::validateData(const std::vector<uint8_t> &data)
    {
        std::stringstream ss;
        ss << "Validating data of size " << data.size() << " bytes";
        CryptoLogger::debug(ss.str());

        if (data.empty())
        {
            CryptoLogger::error("Input data is empty");
            throw InvalidBlockSize("Input data is empty");
        }

        if (data.size() % BlockSize != 0)
        {
            ss.str("");
            ss << "Invalid data length: " << data.size()
               << " (must be multiple of " << BlockSize << ")";
            CryptoLogger::error(ss.str());
            throw InvalidBlockSize("Input data length must be a multiple of " +
                                   std::to_string(BlockSize) + " bytes");
        }

        CryptoLogger::debug("Data validation successful");
    }

    void ModernSymmetricImpl::checkKeyRotation()
    {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::hours>(
                            now - lastOperationTime)
                            .count();

        // Check if key needs rotation based on operation count and time
        if (encryptionCounter > MaxOperationsPerKey || duration > MaxKeyAgeHours)
        {
            CryptoLogger::warning("Key rotation recommended: " +
                                  std::to_string(encryptionCounter) + " operations performed or " +
                                  std::to_string(duration) + " hours elapsed");
        }
    }

    // Add entropy checking for generated values
    bool ModernSymmetricImpl::hasAdequateEntropy(const std::vector<uint8_t> &data)
    {
        if (data.size() < 16)
            return false;

        std::array<unsigned int, 256> frequency{};
        for (uint8_t byte : data)
        {
            frequency[byte]++;
        }

        // Chi-square test for randomness
        double chiSquare = 0.0;
        double expected = static_cast<double>(data.size()) / 256.0;

        for (size_t i = 0; i < 256; i++)
        {
            double diff = frequency[i] - expected;
            chiSquare += (diff * diff) / expected;
        }

        // Critical value for 255 degrees of freedom at 0.01 significance
        return chiSquare < 310.457;
    }

    void ModernSymmetricImpl::prepareAESNI(const std::vector<uint8_t> &key)
    {
#ifdef USE_AES_NI
        if (!useHardwareAES || !AESNIImpl::available())
        {
            throw std::runtime_error("AES-NI not available");
        }

        try
        {
            CryptoLogger::debug("Preparing AES-NI round keys");

            // Clear any existing round keys
            aesniRoundKeys.clear();

            // Generate new round keys
            aesniRoundKeys = AESNIImpl::prepareRoundKeys(key, nr);

            if (aesniRoundKeys.empty() || aesniRoundKeys.size() != static_cast<size_t>(nr + 1))
            {
                throw std::runtime_error("Failed to generate round keys");
            }

            CryptoLogger::debug("AES-NI round keys prepared successfully");
        }
        catch (const std::exception &e)
        {
            CryptoLogger::error("Failed to prepare AES-NI round keys: " + std::string(e.what()));
            useHardwareAES = false;
            throw;
        }
#else
        useHardwareAES = false;
        throw std::runtime_error("AES-NI support not compiled in");
#endif
    }
} // namespace crypto