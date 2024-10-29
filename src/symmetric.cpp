// symmetric.cpp
#include "symmetric.hpp"
#include <cstring>

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
          nr(keyLengthToRounds(keyLength))
    {
        CryptoLogger::info("Initializing AES with " +
                           std::to_string(static_cast<int>(keyLength) * 8) +
                           " bit key length");
    }

    uint8_t ModernSymmetricImpl::xtime(uint8_t b) const
    {
        return (b << 1) ^ ((b & 0x80) ? 0x1B : 0x00);
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
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                uint8_t val = state[i][j];
                state[i][j] = SBOX[val >> 4][val & 0x0F];
            }
        }
    }

    void ModernSymmetricImpl::invSubBytes(uint8_t state[4][4])
    {
        CryptoLogger::trace("Applying Inverse SubBytes transformation");
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                uint8_t val = state[i][j];
                state[i][j] = INV_SBOX[val >> 4][val & 0x0F];
            }
        }
    }

    void ModernSymmetricImpl::shiftRows(uint8_t state[4][4])
    {
        CryptoLogger::trace("Applying ShiftRows transformation");
        // Store temporary values
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

        // Row 3: shift left by 3 (equivalent to right by 1)
        temp = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = temp;
    }

    void ModernSymmetricImpl::invShiftRows(uint8_t state[4][4])
    {
        CryptoLogger::trace("Applying Inverse ShiftRows transformation");
        uint8_t temp;

        // Row 1: shift right by 1
        temp = state[1][3];
        state[1][3] = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = state[1][0];
        state[1][0] = temp;

        // Row 2: shift right by 2
        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;

        // Row 3: shift right by 3 (equivalent to left by 1)
        temp = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = temp;
    }

    void ModernSymmetricImpl::mixColumns(uint8_t state[4][4])
    {
        CryptoLogger::trace("Applying MixColumns transformation");
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
        }

        std::memcpy(state, temp, 16);
    }

    void ModernSymmetricImpl::invMixColumns(uint8_t state[4][4])
    {
        CryptoLogger::trace("Applying Inverse MixColumns transformation");
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
        }

        std::memcpy(state, temp, 16);
    }

    std::vector<uint8_t> ModernSymmetricImpl::expandKey(const std::vector<uint8_t> &key)
    {
        const size_t Nk = static_cast<size_t>(keyLength);
        const size_t expandedKeySize = 4 * Nb * (nr + 1);

        // Pre-allocate expanded key buffer
        std::vector<uint8_t> expandedKey(expandedKeySize);
        std::memcpy(expandedKey.data(), key.data(), key.size());

        // Temporary buffer for word operations
        alignas(16) uint8_t temp[4];

        // Expand the key with minimal logging
        const bool isDebugEnabled = CryptoLogger::get_debug_mode();

        size_t i = Nk;
        while (i < expandedKeySize / 4)
        {
            std::memcpy(temp, &expandedKey[(i - 1) * 4], 4);

            if (i % Nk == 0)
            {
                // Rotate word
                uint8_t tempByte = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = tempByte;

                // S-box substitution
                for (size_t j = 0; j < 4; j++)
                {
                    temp[j] = SBOX[temp[j] >> 4][temp[j] & 0x0F];
                }

                temp[0] ^= RCON[i / Nk - 1];
            }
            else if (Nk > 6 && i % Nk == 4)
            {
                // Additional S-box for AES-256
                for (size_t j = 0; j < 4; j++)
                {
                    temp[j] = SBOX[temp[j] >> 4][temp[j] & 0x0F];
                }
            }

            // XOR with word Nk positions earlier
            for (size_t j = 0; j < 4; j++)
            {
                expandedKey[i * 4 + j] = expandedKey[(i - Nk) * 4 + j] ^ temp[j];
            }

            i++;
        }

        if (isDebugEnabled)
        {
            CryptoLogger::debug("Key expansion completed");
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

    void ModernSymmetricImpl::encryptBlock(
        const uint8_t in[BlockSize],
        uint8_t out[BlockSize],
        const std::vector<uint8_t> &roundKeys)
    {
        // Use aligned state array to ensure proper memory alignment
        alignas(16) uint8_t state[4][4];

        // Load input into state array directly in column-major format
        // This eliminates one format conversion and reduces cache misses
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                state[j][i] = in[i * 4 + j];
            }
        }

        // Initial round key addition
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                state[j][i] ^= roundKeys[i * 4 + j];
            }
        }

        // Main rounds
        for (size_t round = 1; round < nr; round++)
        {
            // SubBytes and ShiftRows combined for better cache utilization
            // Store temporary values to avoid extra memory accesses
            uint8_t temp;

            // Row 0: No shift, only SubBytes
            for (int i = 0; i < 4; i++)
            {
                state[0][i] = SBOX[state[0][i] >> 4][state[0][i] & 0x0F];
            }

            // Row 1: Shift left by 1
            temp = state[1][0];
            state[1][0] = SBOX[state[1][1] >> 4][state[1][1] & 0x0F];
            state[1][1] = SBOX[state[1][2] >> 4][state[1][2] & 0x0F];
            state[1][2] = SBOX[state[1][3] >> 4][state[1][3] & 0x0F];
            state[1][3] = SBOX[temp >> 4][temp & 0x0F];

            // Row 2: Shift left by 2
            temp = state[2][0];
            state[2][0] = SBOX[state[2][2] >> 4][state[2][2] & 0x0F];
            state[2][2] = SBOX[temp >> 4][temp & 0x0F];
            temp = state[2][1];
            state[2][1] = SBOX[state[2][3] >> 4][state[2][3] & 0x0F];
            state[2][3] = SBOX[temp >> 4][temp & 0x0F];

            // Row 3: Shift left by 3 (right by 1)
            temp = state[3][3];
            state[3][3] = SBOX[state[3][2] >> 4][state[3][2] & 0x0F];
            state[3][2] = SBOX[state[3][1] >> 4][state[3][1] & 0x0F];
            state[3][1] = SBOX[state[3][0] >> 4][state[3][0] & 0x0F];
            state[3][0] = SBOX[temp >> 4][temp & 0x0F];

            // MixColumns
            alignas(16) uint8_t temp_state[4][4];
            for (int col = 0; col < 4; col++)
            {
                // Save original column values
                uint8_t s0 = state[0][col];
                uint8_t s1 = state[1][col];
                uint8_t s2 = state[2][col];
                uint8_t s3 = state[3][col];

                temp_state[0][col] =
                    xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3;
                temp_state[1][col] =
                    s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3;
                temp_state[2][col] =
                    s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3;
                temp_state[3][col] =
                    xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3);
            }
            std::memcpy(state, temp_state, 16);

            // AddRoundKey with direct indexing
            const uint8_t *roundKey = roundKeys.data() + (round * 16);
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[j][i] ^= roundKey[i * 4 + j];
                }
            }
        }

        // Final round (no MixColumns)
        // Combined SubBytes, ShiftRows, and AddRoundKey
        alignas(16) uint8_t final_state[4][4];
        const uint8_t *finalKey = roundKeys.data() + (nr * 16);

        // Row 0: No shift
        for (int i = 0; i < 4; i++)
        {
            final_state[0][i] = SBOX[state[0][i] >> 4][state[0][i] & 0x0F] ^ finalKey[i * 4];
        }

        // Row 1: Shift left by 1
        final_state[1][0] = SBOX[state[1][1] >> 4][state[1][1] & 0x0F] ^ finalKey[1];
        final_state[1][1] = SBOX[state[1][2] >> 4][state[1][2] & 0x0F] ^ finalKey[5];
        final_state[1][2] = SBOX[state[1][3] >> 4][state[1][3] & 0x0F] ^ finalKey[9];
        final_state[1][3] = SBOX[state[1][0] >> 4][state[1][0] & 0x0F] ^ finalKey[13];

        // Row 2: Shift left by 2
        final_state[2][0] = SBOX[state[2][2] >> 4][state[2][2] & 0x0F] ^ finalKey[2];
        final_state[2][1] = SBOX[state[2][3] >> 4][state[2][3] & 0x0F] ^ finalKey[6];
        final_state[2][2] = SBOX[state[2][0] >> 4][state[2][0] & 0x0F] ^ finalKey[10];
        final_state[2][3] = SBOX[state[2][1] >> 4][state[2][1] & 0x0F] ^ finalKey[14];

        // Row 3: Shift right by 1
        final_state[3][0] = SBOX[state[3][3] >> 4][state[3][3] & 0x0F] ^ finalKey[3];
        final_state[3][1] = SBOX[state[3][0] >> 4][state[3][0] & 0x0F] ^ finalKey[7];
        final_state[3][2] = SBOX[state[3][1] >> 4][state[3][1] & 0x0F] ^ finalKey[11];
        final_state[3][3] = SBOX[state[3][2] >> 4][state[3][2] & 0x0F] ^ finalKey[15];

        // Store result directly in column-major format
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                out[i * 4 + j] = final_state[j][i];
            }
        }
    }

    void ModernSymmetricImpl::decryptBlock(
        const uint8_t in[BlockSize],
        uint8_t out[BlockSize],
        const std::vector<uint8_t> &roundKeys)
    {
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

        // Initial round
        const uint8_t *lastKey = roundKeys.data() + (nr * 16);
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                state[j][i] ^= lastKey[i * 4 + j];
            }
        }

        // Combined InvShiftRows and InvSubBytes for better cache utilization
        for (size_t round = nr - 1; round > 0; --round)
        {
            // First do InvShiftRows
            uint8_t temp;

            // Row 0: No shift (stays the same)

            // Row 1: Shift right by 1
            temp = state[1][3];
            state[1][3] = state[1][2];
            state[1][2] = state[1][1];
            state[1][1] = state[1][0];
            state[1][0] = temp;

            // Row 2: Shift right by 2
            std::swap(state[2][0], state[2][2]);
            std::swap(state[2][1], state[2][3]);

            // Row 3: Shift right by 3 (left by 1)
            temp = state[3][0];
            state[3][0] = state[3][1];
            state[3][1] = state[3][2];
            state[3][2] = state[3][3];
            state[3][3] = temp;

            // Then do InvSubBytes
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[i][j] = INV_SBOX[state[i][j] >> 4][state[i][j] & 0x0F];
                }
            }

            // Then AddRoundKey
            const uint8_t *roundKey = roundKeys.data() + (round * 16);
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[j][i] ^= roundKey[i * 4 + j];
                }
            }

            // Finally InvMixColumns
            alignas(16) uint8_t temp_state[4][4];
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    uint8_t a = state[row][col];
                    uint8_t b = xtime(a);
                    uint8_t c = xtime(b);
                    uint8_t d = xtime(c);

                    temp_state[row][col] =
                        (d ^ c ^ b) ^ // 0x0e * a
                        (d ^ b ^ a) ^ // 0x0b * next
                        (d ^ c ^ a) ^ // 0x0d * next
                        (d ^ a);      // 0x09 * last
                }
            }
            std::memcpy(state, temp_state, 16);
        }
        // Final round (no InvMixColumns)
        // Combined InvShiftRows, InvSubBytes, and AddRoundKey
        alignas(16) uint8_t final_state[4][4];

        // Row 0: No shift
        for (int i = 0; i < 4; i++)
        {
            final_state[0][i] = INV_SBOX[state[0][i] >> 4][state[0][i] & 0x0F] ^ roundKeys[0 + i * 4];
        }

        // Row 1: Shift right by 1
        final_state[1][0] = INV_SBOX[state[1][3] >> 4][state[1][3] & 0x0F] ^ roundKeys[1];
        final_state[1][1] = INV_SBOX[state[1][0] >> 4][state[1][0] & 0x0F] ^ roundKeys[5];
        final_state[1][2] = INV_SBOX[state[1][1] >> 4][state[1][1] & 0x0F] ^ roundKeys[9];
        final_state[1][3] = INV_SBOX[state[1][2] >> 4][state[1][2] & 0x0F] ^ roundKeys[13];

        // Row 2: Shift right by 2
        final_state[2][0] = INV_SBOX[state[2][2] >> 4][state[2][2] & 0x0F] ^ roundKeys[2];
        final_state[2][1] = INV_SBOX[state[2][3] >> 4][state[2][3] & 0x0F] ^ roundKeys[6];
        final_state[2][2] = INV_SBOX[state[2][0] >> 4][state[2][0] & 0x0F] ^ roundKeys[10];
        final_state[2][3] = INV_SBOX[state[2][1] >> 4][state[2][1] & 0x0F] ^ roundKeys[14];

        // Row 3: Shift left by 1
        final_state[3][0] = INV_SBOX[state[3][1] >> 4][state[3][1] & 0x0F] ^ roundKeys[3];
        final_state[3][1] = INV_SBOX[state[3][2] >> 4][state[3][2] & 0x0F] ^ roundKeys[7];
        final_state[3][2] = INV_SBOX[state[3][3] >> 4][state[3][3] & 0x0F] ^ roundKeys[11];
        final_state[3][3] = INV_SBOX[state[3][0] >> 4][state[3][0] & 0x0F] ^ roundKeys[15];

        // Store result directly in column-major format
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                out[i * 4 + j] = final_state[j][i];
            }
        }
    }

    std::vector<uint8_t> ModernSymmetricImpl::addPKCS7Padding(const std::vector<uint8_t> &data)
    {
        // Calculate padding length - if data length is multiple of block size,
        // add a full block of padding
        const size_t paddingLength =
            data.size() % BlockSize == 0 ? BlockSize : BlockSize - (data.size() % BlockSize);

        // Pre-allocate the exact size needed
        std::vector<uint8_t> paddedData;
        paddedData.reserve(data.size() + paddingLength);

        // Copy original data
        paddedData.insert(paddedData.end(), data.begin(), data.end());

        // Add padding bytes
        const uint8_t paddingByte = static_cast<uint8_t>(paddingLength);
        paddedData.insert(paddedData.end(), paddingLength, paddingByte);

        return paddedData;
    }

    std::vector<uint8_t> ModernSymmetricImpl::removePKCS7Padding(const std::vector<uint8_t> &data)
    {
        if (data.empty())
        {
            throw AESException("Cannot remove padding from empty data");
        }

        validateBlockAlignment(data.size(), "Padded data");

        // Get padding length from last byte
        const uint8_t paddingLength = data.back();

        // Strict validation of padding length
        if (paddingLength == 0 || paddingLength > BlockSize || paddingLength > data.size())
        {
            throw AESException("Invalid padding length: " + std::to_string(paddingLength));
        }

        // Verify all padding bytes
        const size_t messageLength = data.size() - paddingLength;
        for (size_t i = messageLength; i < data.size(); i++)
        {
            if (data[i] != paddingLength)
            {
                throw AESException("Invalid padding bytes");
            }
        }

        // Return data without padding
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

            CryptoLogger::info("Starting ECB encryption operation");
            CryptoLogger::warning("ECB mode is not recommended for secure operations");

            std::vector<uint8_t> paddedData = addPKCS7Padding(data);
            CryptoLogger::debug("Prepared " + std::to_string(paddedData.size()) +
                                " bytes of padded data for ECB encryption");

            std::vector<uint8_t> roundKeys = expandKey(key);
            std::vector<uint8_t> output(paddedData.size());

            for (size_t i = 0; i < paddedData.size(); i += BlockSize)
            {
                CryptoLogger::trace("Processing ECB block " + std::to_string(i / BlockSize + 1) +
                                    " of " + std::to_string(paddedData.size() / BlockSize));
                encryptBlock(paddedData.data() + i, output.data() + i, roundKeys);
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
            if (data.empty())
            {
                throw InvalidBlockSize("Input data is empty");
            }

            const std::vector<uint8_t> paddedData = addPKCS7Padding(data);
            std::vector<uint8_t> output(paddedData.size());
            const std::vector<uint8_t> roundKeys = expandKey(key);

            // Stack-allocated buffers
            alignas(16) uint8_t blockBuffer[BlockSize];
            alignas(16) uint8_t prevBlock[BlockSize];
            std::memcpy(prevBlock, iv.data(), BlockSize);

            const size_t numBlocks = paddedData.size() / BlockSize;
            const bool isDebugEnabled = CryptoLogger::get_debug_mode();
            if (isDebugEnabled)
            {
                CryptoLogger::debug("Starting CBC encryption of " + std::to_string(numBlocks) + " blocks");
            }

            for (size_t i = 0; i < paddedData.size(); i += BlockSize)
            {
                // XOR with previous block
                for (size_t j = 0; j < BlockSize; j++)
                {
                    blockBuffer[j] = paddedData[i + j] ^ prevBlock[j];
                }

                // Encrypt block
                encryptBlock(blockBuffer, output.data() + i, roundKeys);

                // Update previous block
                std::memcpy(prevBlock, output.data() + i, BlockSize);
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

            CryptoLogger::debug("Starting CFB encryption");

            std::vector<uint8_t> roundKeys = expandKey(key);
            std::vector<uint8_t> output(data.size());
            std::vector<uint8_t> previousBlock = iv;
            std::vector<uint8_t> encryptedBlock(BlockSize);

            size_t processedBytes = 0;
            while (processedBytes < data.size())
            {
                encryptBlock(previousBlock.data(), encryptedBlock.data(), roundKeys);

                size_t bytesToProcess = std::min(BlockSize, data.size() - processedBytes);
                for (size_t j = 0; j < bytesToProcess; j++)
                {
                    output[processedBytes + j] = data[processedBytes + j] ^ encryptedBlock[j];
                }

                previousBlock = encryptedBlock;
                processedBytes += bytesToProcess;
            }

            CryptoLogger::debug("CFB encryption completed successfully");
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

            CryptoLogger::debug("Starting OFB encryption");

            std::vector<uint8_t> roundKeys = expandKey(key);
            std::vector<uint8_t> output(data.size());
            std::vector<uint8_t> keystream = iv;

            size_t processedBytes = 0;
            while (processedBytes < data.size())
            {
                encryptBlock(keystream.data(), keystream.data(), roundKeys);

                size_t bytesToProcess = std::min(BlockSize, data.size() - processedBytes);
                for (size_t j = 0; j < bytesToProcess; j++)
                {
                    output[processedBytes + j] = data[processedBytes + j] ^ keystream[j];
                }

                processedBytes += bytesToProcess;
            }

            CryptoLogger::debug("OFB encryption completed successfully");
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

            CryptoLogger::debug("Starting ECB decryption");

            std::vector<uint8_t> roundKeys = expandKey(key);
            std::vector<uint8_t> output(data.size());

            for (size_t i = 0; i < data.size(); i += BlockSize)
            {
                decryptBlock(data.data() + i, output.data() + i, roundKeys);
            }

            // Remove padding after decryption
            std::vector<uint8_t> unpaddedData = removePKCS7Padding(output);
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

            const std::vector<uint8_t> roundKeys = expandKey(key);
            std::vector<uint8_t> output(data.size());

            // Stack-allocated buffers
            alignas(16) uint8_t decryptBuffer[BlockSize];
            alignas(16) uint8_t prevBlock[BlockSize];
            alignas(16) uint8_t currBlock[BlockSize];
            std::memcpy(prevBlock, iv.data(), BlockSize);

            for (size_t i = 0; i < data.size(); i += BlockSize)
            {
                // Save current ciphertext block
                std::memcpy(currBlock, data.data() + i, BlockSize);

                // Decrypt block
                decryptBlock(data.data() + i, decryptBuffer, roundKeys);

                // XOR with previous block
                for (size_t j = 0; j < BlockSize; j++)
                {
                    output[i + j] = decryptBuffer[j] ^ prevBlock[j];
                }

                // Update previous block
                std::memcpy(prevBlock, currBlock, BlockSize);
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
            validateData(data);
            validateIV(iv);
            CryptoLogger::debug("Starting CFB decryption");

            std::vector<uint8_t> roundKeys = expandKey(key);
            std::vector<uint8_t> output(data.size());
            std::vector<uint8_t> previousBlock = iv;
            std::vector<uint8_t> encryptedBlock(BlockSize);

            for (size_t i = 0; i < data.size(); i += BlockSize)
            {
                // Encrypt previous block
                encryptBlock(previousBlock.data(), encryptedBlock.data(), roundKeys);

                // XOR with ciphertext to get plaintext
                for (size_t j = 0; j < BlockSize; j++)
                {
                    output[i + j] = data[i + j] ^ encryptedBlock[j];
                }

                // Update previous block for next iteration
                previousBlock.assign(data.begin() + i, data.begin() + i + BlockSize);
            }

            CryptoLogger::debug("CFB decryption completed successfully");
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
        return aesEncryptOFB(data, key, iv); // OFB mode is symmetric
    }

    void ModernSymmetricImpl::validateKey(const std::vector<uint8_t> &key)
    {
        CryptoLogger::debug("Validating key of length " + std::to_string(key.size()) + " bytes");

        if (key.size() != static_cast<size_t>(keyLength))
        {
            CryptoLogger::error("Invalid key length: " + std::to_string(key.size()) +
                                " bytes (expected " + std::to_string(static_cast<size_t>(keyLength)) +
                                " bytes)");
            throw InvalidKeyLength("Invalid key length: " + std::to_string(key.size()) +
                                   " bytes (expected " + std::to_string(static_cast<size_t>(keyLength)) +
                                   " bytes)");
        }

        // Check key entropy
        bool hasLowEntropy = false;
        uint8_t firstByte = key[0];
        for (const auto &byte : key)
        {
            if (byte != firstByte)
            {
                hasLowEntropy = false;
                break;
            }
            hasLowEntropy = true;
        }

        if (hasLowEntropy)
        {
            CryptoLogger::warning("Key has low entropy - all bytes are identical");
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
        if (size == 0)
        {
            throw InvalidBlockSize(context + " is empty");
        }

        if (size % BlockSize != 0)
        {
            throw InvalidBlockSize(context + " size (" + std::to_string(size) +
                                   ") must be a multiple of " + std::to_string(BlockSize) + " bytes");
        }
    }

    // Constant-time comparison to prevent timing attacks
    bool ModernSymmetricImpl::constantTimeMemEqual(const void *a, const void *b, size_t size)
    {
        const volatile unsigned char *aa = static_cast<const volatile unsigned char *>(a);
        const volatile unsigned char *bb = static_cast<const volatile unsigned char *>(b);
        volatile unsigned char result = 0;

        for (size_t i = 0; i < size; ++i)
        {
            result |= aa[i] ^ bb[i];
        }

        return result == 0;
    }

    // Secure memory wiping
    void ModernSymmetricImpl::secureZero(void *ptr, size_t size)
    {
        volatile unsigned char *p = static_cast<volatile unsigned char *>(ptr);
        while (size--)
        {
            *p++ = 0;
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
            throw AESException("Null pointer provided for " + context);
        }
    }

    void ModernSymmetricImpl::validateData(const std::vector<uint8_t> &data)
    {
        if (data.empty())
        {
            throw InvalidBlockSize("Input data is empty");
        }
        if (data.size() % BlockSize != 0)
        {
            throw InvalidBlockSize("Input data length must be a multiple of " +
                                   std::to_string(BlockSize) + " bytes");
        }
    }

} // namespace crypto