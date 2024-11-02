// aes_ni.hpp
#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include "crypto_logger.hpp"

#if defined(__x86_64__) || defined(_M_X64)
    #include <immintrin.h>
    #include <wmmintrin.h>
    #define USE_AES_NI

    #ifdef _MSC_VER
        #include <intrin.h> // For Windows CPUID
    #else
        #include <cpuid.h> // For Unix/Linux CPUID
    #endif
#endif

namespace crypto
{

class AESNIImpl
{

private:
    static const size_t ENCRYPTION_KEY_OFFSET = 0;
    static const size_t DECRYPTION_KEY_OFFSET = 11;
public:
    static bool available()
    {
#ifdef USE_AES_NI
    #ifdef _MSC_VER
        // Windows implementation
        int cpuInfo[4];
        __cpuid(cpuInfo, 1);
        bool hasAESNI = (cpuInfo[2] & (1 << 25)) != 0;
    #else
        // Unix/Linux implementation
        unsigned int eax, ebx, ecx, edx;
        if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
        {
            CryptoLogger::warning("Failed to get CPU info");
            return false;
        }
        bool hasAESNI = (ecx & (1 << 25)) != 0;
    #endif
        CryptoLogger::debug("AES-NI Support: " + std::string(hasAESNI ? "Yes" : "No"));
        return hasAESNI;
#else
        return false;
#endif
    }

#ifdef USE_AES_NI
    static void encryptBlock(const uint8_t in[16], uint8_t out[16],
                           const __m128i *roundKeys, int rounds)
    {
        __m128i m = _mm_loadu_si128(reinterpret_cast<const __m128i *>(in));

        // Use encryption keys from the first half
        m = _mm_xor_si128(m, roundKeys[ENCRYPTION_KEY_OFFSET]); // Initial round

        // Main rounds
        for (int i = 1; i < rounds; i++)
        {
            m = _mm_aesenc_si128(m, roundKeys[ENCRYPTION_KEY_OFFSET + i]);
        }

        // Final round
        m = _mm_aesenclast_si128(m, roundKeys[ENCRYPTION_KEY_OFFSET + rounds]);

        _mm_storeu_si128(reinterpret_cast<__m128i *>(out), m);
    }

    static void decryptBlock(const uint8_t in[16], uint8_t out[16],
                       const __m128i *roundKeys, int rounds)
{
    CryptoLogger::debug("Starting AES-NI block decryption");
    
    __m128i m = _mm_loadu_si128(reinterpret_cast<const __m128i *>(in));

    // Use decryption keys from the second half
    m = _mm_xor_si128(m, roundKeys[DECRYPTION_KEY_OFFSET + rounds]); // Initial round

    // Main rounds
    for (int i = rounds - 1; i > 0; i--)
    {
        m = _mm_aesdec_si128(m, roundKeys[DECRYPTION_KEY_OFFSET + i]);
    }

    // Final round
    m = _mm_aesdeclast_si128(m, roundKeys[DECRYPTION_KEY_OFFSET]);

    _mm_storeu_si128(reinterpret_cast<__m128i *>(out), m);
    
    CryptoLogger::debug("AES-NI block decryption completed");
}

    static std::vector<__m128i> prepareRoundKeys(const std::vector<uint8_t> &key, int rounds)
{
    CryptoLogger::debug("Preparing AES-NI round keys");

    std::vector<__m128i> roundKeys((rounds + 1) * 2);  // Space for both encryption and decryption keys
    
    // Load initial key
    roundKeys[0] = _mm_loadu_si128(reinterpret_cast<const __m128i *>(key.data()));
    __m128i temp1 = roundKeys[0];

    // Generate encryption round keys
    for (int i = 1; i <= rounds; ++i)
    {
        __m128i temp2;
        switch(i) {
            case 1:  temp2 = _mm_aeskeygenassist_si128(temp1, 0x01); break;
            case 2:  temp2 = _mm_aeskeygenassist_si128(temp1, 0x02); break;
            case 3:  temp2 = _mm_aeskeygenassist_si128(temp1, 0x04); break;
            case 4:  temp2 = _mm_aeskeygenassist_si128(temp1, 0x08); break;
            case 5:  temp2 = _mm_aeskeygenassist_si128(temp1, 0x10); break;
            case 6:  temp2 = _mm_aeskeygenassist_si128(temp1, 0x20); break;
            case 7:  temp2 = _mm_aeskeygenassist_si128(temp1, 0x40); break;
            case 8:  temp2 = _mm_aeskeygenassist_si128(temp1, 0x80); break;
            case 9:  temp2 = _mm_aeskeygenassist_si128(temp1, 0x1B); break;
            case 10: temp2 = _mm_aeskeygenassist_si128(temp1, 0x36); break;
            default: throw std::runtime_error("Invalid round number");
        }

        temp2 = _mm_shuffle_epi32(temp2, 0xff);
        temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
        temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
        temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
        temp1 = _mm_xor_si128(temp1, temp2);
        
        roundKeys[i] = temp1;
        
        // Log encryption round key
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&roundKeys[i]);
        std::stringstream ss;
        ss << "Encryption round key " << i << ": ";
        for (int j = 0; j < 16; j++) {
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(bytes[j]) << " ";
        }
        CryptoLogger::debug(ss.str());
    }

    // Generate decryption round keys
    for (int i = 1; i < rounds; i++) {
        roundKeys[DECRYPTION_KEY_OFFSET + i] = _mm_aesimc_si128(roundKeys[i]);
        
        // Log decryption round key
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&roundKeys[DECRYPTION_KEY_OFFSET + i]);
        std::stringstream ss;
        ss << "Decryption round key " << i << ": ";
        for (int j = 0; j < 16; j++) {
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(bytes[j]) << " ";
        }
        CryptoLogger::debug(ss.str());
    }
    
    // First and last round keys stay the same
    roundKeys[DECRYPTION_KEY_OFFSET] = roundKeys[0];
    roundKeys[DECRYPTION_KEY_OFFSET + rounds] = roundKeys[rounds];

    CryptoLogger::debug("Generated " + std::to_string(roundKeys.size()) +
                       " round keys (including decryption keys) for AES-NI");
    return roundKeys;
}
#endif

    // Perform aligned memory allocation for SIMD operations
    static std::unique_ptr<uint8_t[]> alignedAlloc(size_t size)
    {
        void *ptr = nullptr;
#ifdef _MSC_VER
        ptr = _aligned_malloc(size, 16);
#else
        if (posix_memalign(&ptr, 16, size) != 0)
        {
            ptr = nullptr;
        }
#endif
        return std::unique_ptr<uint8_t[]>(static_cast<uint8_t *>(ptr));
    }

    static void alignedFree(void *ptr)
    {
#ifdef _MSC_VER
        _aligned_free(ptr);
#else
        free(ptr);
#endif
    }
};

} // namespace crypto