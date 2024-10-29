// hash.cpp
#include "hash.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>

namespace crypto
{

    // Initialize SHA-256 constants
    const std::array<uint32_t, 64> HashImpl::K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    // Helper functions for SHA-256 operations
    uint32_t HashImpl::ch(uint32_t x, uint32_t y, uint32_t z)
    {
        return (x & y) ^ (~x & z);
    }

    uint32_t HashImpl::maj(uint32_t x, uint32_t y, uint32_t z)
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    uint32_t HashImpl::rotr(uint32_t x, unsigned int n)
    {
        return (x >> n) | (x << (32 - n));
    }

    uint32_t HashImpl::shr(uint32_t x, unsigned int n)
    {
        return x >> n;
    }

    uint32_t HashImpl::sigma0(uint32_t x)
    {
        return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3);
    }

    uint32_t HashImpl::sigma1(uint32_t x)
    {
        return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10);
    }

    uint32_t HashImpl::Sigma0(uint32_t x)
    {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    uint32_t HashImpl::Sigma1(uint32_t x)
    {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    // Utility functions for byte manipulation
    uint32_t HashImpl::bytesToUInt32(const uint8_t *bytes)
    {
        // Explicitly handle big-endian conversion
        return (static_cast<uint32_t>(bytes[0]) << 24) |
               (static_cast<uint32_t>(bytes[1]) << 16) |
               (static_cast<uint32_t>(bytes[2]) << 8) |
               (static_cast<uint32_t>(bytes[3]));
    }

    void HashImpl::uint32ToBytes(uint32_t value, uint8_t *bytes)
    {
        // Explicitly handle big-endian conversion
        bytes[0] = static_cast<uint8_t>(value >> 24);
        bytes[1] = static_cast<uint8_t>(value >> 16);
        bytes[2] = static_cast<uint8_t>(value >> 8);
        bytes[3] = static_cast<uint8_t>(value);
    }

    void HashImpl::validateInput(const std::vector<uint8_t> &input)
    {
        // Check for maximum input size (2^64 bits = 2^61 bytes)
        if (input.size() > ((1ULL << 61) - 1))
        {
            throw InvalidHashInput("Input size exceeds maximum allowed (2^64 - 1 bits)");
        }
    }

    void HashImpl::resetState()
    {
        // Reset to initial hash values
        state = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    }

    std::vector<uint8_t> HashImpl::pad(const std::vector<uint8_t> &message)
    {
        uint64_t msgLenBits = message.size() * 8ULL;
        size_t curLen = message.size() % BLOCK_SIZE;
        size_t paddingLen;

        if (curLen < 56)
        {
            paddingLen = 56 - curLen;
        }
        else
        {
            paddingLen = 120 - curLen; // Go to next block
        }

        std::vector<uint8_t> padded;
        padded.reserve(message.size() + paddingLen + 8);

        // Original message
        padded.insert(padded.end(), message.begin(), message.end());

        // Padding bits
        padded.push_back(0x80); // 1 followed by zeros
        padded.resize(padded.size() + paddingLen - 1, 0x00);

        // Length in bits as big-endian 64-bit integer
        for (int i = 7; i >= 0; --i)
        {
            padded.push_back(static_cast<uint8_t>(msgLenBits >> (i * 8)));
        }

        return padded;
    }

    void HashImpl::processBlock(const uint8_t *block)
    {
        uint32_t w[64];

        // Load initial 16 words
        for (int t = 0; t < 16; ++t)
        {
            w[t] = bytesToUInt32(&block[t * 4]);
        }

        // Message schedule
        for (int t = 16; t < 64; ++t)
        {
            uint32_t s0 = sigma0(w[t - 15]);
            uint32_t s1 = sigma1(w[t - 2]);
            w[t] = w[t - 16] + s0 + w[t - 7] + s1;
        }

        // Working variables
        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];

        // Compression loop
        for (int t = 0; t < 64; ++t)
        {
            uint32_t S1 = Sigma1(e);
            uint32_t ch_efg = ch(e, f, g);
            uint32_t temp1 = h + S1 + ch_efg;
            temp1 = temp1 + K[t];
            temp1 = temp1 + w[t];

            uint32_t S0 = Sigma0(a);
            uint32_t maj_abc = maj(a, b, c);
            uint32_t temp2 = S0 + maj_abc;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // Update state with carry
        state[0] = state[0] + a;
        state[1] = state[1] + b;
        state[2] = state[2] + c;
        state[3] = state[3] + d;
        state[4] = state[4] + e;
        state[5] = state[5] + f;
        state[6] = state[6] + g;
        state[7] = state[7] + h;
    }

    std::vector<uint8_t> HashImpl::sha256(const std::vector<uint8_t> &message)
    {
        try
        {
            validateInput(message);
            resetState();

            std::vector<uint8_t> paddedMessage = pad(message);
            const size_t numBlocks = paddedMessage.size() / BLOCK_SIZE;

            // Process each block
            for (size_t i = 0; i < numBlocks; ++i)
            {
                if (i % 1000 == 0)
                { // Log progress for large inputs
                    CryptoLogger::debug("Processing block " + std::to_string(i) +
                                        " of " + std::to_string(numBlocks));
                }
                processBlock(&paddedMessage[i * BLOCK_SIZE]);
            }

            // Prepare final hash
            std::vector<uint8_t> hash(HASH_SIZE);
            for (int i = 0; i < 8; ++i)
            {
                uint32ToBytes(state[i], &hash[i * 4]);
            }

            return hash;
        }
        catch (const std::exception &e)
        {
            CryptoLogger::error("SHA-256 computation failed: " + std::string(e.what()));
            throw;
        }
    }

    std::vector<uint8_t> HashImpl::sha256(const std::string &message)
    {
        return sha256(std::vector<uint8_t>(message.begin(), message.end()));
    }

    std::vector<uint8_t> HashImpl::hmacSha256(const std::vector<uint8_t> &message,
                                              const std::vector<uint8_t> &key)
    {
        CryptoLogger::debug("Starting HMAC-SHA256 computation");

        // HMAC constants
        const uint8_t IPAD = 0x36;
        const uint8_t OPAD = 0x5c;

        try
        {
            // Prepare key
            std::vector<uint8_t> normalizedKey;
            if (key.size() > BLOCK_SIZE)
            {
                normalizedKey = sha256(key);
                normalizedKey.resize(BLOCK_SIZE, 0x00);
            }
            else
            {
                normalizedKey = key;
                normalizedKey.resize(BLOCK_SIZE, 0x00);
            }

            // Inner hash
            std::vector<uint8_t> innerPadding(BLOCK_SIZE);
            for (size_t i = 0; i < BLOCK_SIZE; ++i)
            {
                innerPadding[i] = normalizedKey[i] ^ IPAD;
            }
            innerPadding.insert(innerPadding.end(), message.begin(), message.end());
            std::vector<uint8_t> innerHash = sha256(innerPadding);

            // Outer hash
            std::vector<uint8_t> outerPadding(BLOCK_SIZE);
            for (size_t i = 0; i < BLOCK_SIZE; ++i)
            {
                outerPadding[i] = normalizedKey[i] ^ OPAD;
            }
            outerPadding.insert(outerPadding.end(), innerHash.begin(), innerHash.end());

            CryptoLogger::debug("HMAC-SHA256 computation completed successfully");
            return sha256(outerPadding);
        }
        catch (const std::exception &e)
        {
            CryptoLogger::error("HMAC-SHA256 computation failed");
            CryptoLogger::log_exception(e, "HMAC-SHA256");
            throw;
        }
    }

} // namespace crypto