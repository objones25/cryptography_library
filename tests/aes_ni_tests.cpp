#include <gtest/gtest.h>
#include "aes_ni.hpp"
#include "crypto_logger.hpp"
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <array>

#if defined(__x86_64__) || defined(_M_X64)
    #include <immintrin.h>
    #include <wmmintrin.h>
    #define HAS_AES_NI
#endif

class AESNITest : public ::testing::Test {
protected:
    void SetUp() override {
        crypto::CryptoLogger::set_debug_mode(true);
    }
    
    void TearDown() override {
        crypto::CryptoLogger::set_debug_mode(false);
    }

#ifdef HAS_AES_NI
    // Helper to print __m128i values for debugging
    static std::string m128iToString(__m128i value) {
        std::stringstream ss;
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&value);
        for (int i = 0; i < 16; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(bytes[i]) << " ";
        }
        return ss.str();
    }

    // Helper to compare round keys
    void compareRoundKey(const __m128i& actual1, const __m128i& actual2, 
                        const std::string& description) {
        const uint8_t* bytes1 = reinterpret_cast<const uint8_t*>(&actual1);
        const uint8_t* bytes2 = reinterpret_cast<const uint8_t*>(&actual2);
        for (int i = 0; i < 16; i++) {
            EXPECT_EQ(bytes1[i], bytes2[i])
                << description << " mismatch at byte " << i;
        }
    }

    void compareRoundKey(const __m128i& actual, const std::array<uint8_t, 16>& expected, 
                        const std::string& description) {
        const uint8_t* actual_bytes = reinterpret_cast<const uint8_t*>(&actual);
        for (int i = 0; i < 16; i++) {
            EXPECT_EQ(actual_bytes[i], expected[i])
                << description << " mismatch at byte " << i;
        }
    }
#endif

    // Test vectors
    const std::vector<uint8_t> test_key = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    const std::array<uint8_t, 16> expected_dec_round1 = {{
        0x2b, 0x37, 0x08, 0xa7, 0xf2, 0x62, 0xd4, 0x05,
        0xbc, 0x3e, 0xbd, 0xbf, 0x4b, 0x61, 0x7d, 0x62
    }};

    const std::array<uint8_t, 16> expected_dec_round9 = {{
        0x0c, 0x7b, 0x5a, 0x63, 0x13, 0x19, 0xea, 0xfe,
        0xb0, 0x39, 0x88, 0x90, 0x66, 0x4c, 0xfb, 0xb4
    }};

    void checkAESNIAvailable() {
        if (!crypto::AESNIImpl::available()) {
            GTEST_SKIP() << "AES-NI not available on this CPU";
        }
    }
};

#ifdef HAS_AES_NI
TEST_F(AESNITest, RoundKeyGeneration) {
    checkAESNIAvailable();

    try {
        crypto::CryptoLogger::debug("Starting round key generation test");
        auto roundKeys = crypto::AESNIImpl::prepareRoundKeys(test_key, 10);

        // We expect 22 keys: 11 for encryption and 11 for decryption
        ASSERT_EQ(roundKeys.size(), 22) << "Wrong number of round keys generated";

        // Print each round key for debugging
        for (size_t i = 0; i < roundKeys.size(); i++) {
            if (i <= 10) {
                crypto::CryptoLogger::debug("Encryption round key " + std::to_string(i) + ": " + 
                                  m128iToString(roundKeys[i]));
            } else {
                crypto::CryptoLogger::debug("Decryption round key " + std::to_string(i-11) + ": " + 
                                  m128iToString(roundKeys[i]));
            }
        }

        // Known first round key from NIST test vectors
        const std::array<uint8_t, 16> expected_first_key = {{
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        }};

        // Verify round keys
        compareRoundKey(roundKeys[0], expected_first_key, "First encryption round key");
        compareRoundKey(roundKeys[12], expected_dec_round1, "First transformed decryption round key");
        compareRoundKey(roundKeys[20], expected_dec_round9, "Last transformed decryption round key");
        compareRoundKey(roundKeys[11], roundKeys[0], "First round key copy");
        compareRoundKey(roundKeys[21], roundKeys[10], "Last round key copy");
    }
    catch (const std::exception& e) {
        ADD_FAILURE() << "Exception during round key generation: " << e.what();
    }
}

TEST_F(AESNITest, SingleBlockEncryption) {
    checkAESNIAvailable();

    try {
        // NIST test vector
        const uint8_t plaintext[16] = {
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
        };
        const uint8_t expected[16] = {
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
        };
        uint8_t output[16] = {0};

        auto roundKeys = crypto::AESNIImpl::prepareRoundKeys(test_key, 10);
        ASSERT_FALSE(roundKeys.empty()) << "Round key generation failed";

        crypto::AESNIImpl::encryptBlock(plaintext, output, roundKeys.data(), 10);

        // Verify result
        for (int i = 0; i < 16; i++) {
            EXPECT_EQ(output[i], expected[i])
                << "Mismatch at byte " << i;
        }
    }
    catch (const std::exception& e) {
        ADD_FAILURE() << "Exception during encryption: " << e.what();
    }
}

TEST_F(AESNITest, EncryptDecryptRoundTrip) {
    checkAESNIAvailable();

    try {
        // Test with known input instead of random data
        const uint8_t plaintext[16] = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        };
        
        uint8_t ciphertext[16];
        uint8_t decrypted[16];

        // Generate and store round keys
        auto roundKeys = crypto::AESNIImpl::prepareRoundKeys(test_key, 10);
        ASSERT_FALSE(roundKeys.empty()) << "Round key generation failed";

        // Log the input
        crypto::CryptoLogger::debug("Original plaintext:");
        for (int i = 0; i < 16; i++) {
            std::stringstream ss;
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(plaintext[i]) << " ";
            crypto::CryptoLogger::debug(ss.str());
        }

        // Encrypt
        crypto::AESNIImpl::encryptBlock(plaintext, ciphertext, roundKeys.data(), 10);
        
        // Log the ciphertext
        crypto::CryptoLogger::debug("Ciphertext:");
        for (int i = 0; i < 16; i++) {
            std::stringstream ss;
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(ciphertext[i]) << " ";
            crypto::CryptoLogger::debug(ss.str());
        }

        // Decrypt
        crypto::AESNIImpl::decryptBlock(ciphertext, decrypted, roundKeys.data(), 10);

        // Log the decrypted result
        crypto::CryptoLogger::debug("Decrypted result:");
        for (int i = 0; i < 16; i++) {
            std::stringstream ss;
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(decrypted[i]) << " ";
            crypto::CryptoLogger::debug(ss.str());
        }

        // Verify roundtrip
        for (int i = 0; i < 16; i++) {
            EXPECT_EQ(plaintext[i], decrypted[i])
                << "Roundtrip failed at byte " << i << "\n"
                << "Expected: 0x" << std::hex << static_cast<int>(plaintext[i]) << "\n"
                << "Got: 0x" << std::hex << static_cast<int>(decrypted[i]);
        }
    }
    catch (const std::exception& e) {
        ADD_FAILURE() << "Exception during roundtrip test: " << e.what();
    }
}
#endif // HAS_AES_NI

// Basic availability test that should run on all platforms
TEST_F(AESNITest, CheckAvailability) {
    bool available = crypto::AESNIImpl::available();
    crypto::CryptoLogger::info("AES-NI availability: " + std::string(available ? "Yes" : "No"));
    SUCCEED(); // This test always passes, it just logs the availability
}