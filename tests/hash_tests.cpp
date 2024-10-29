// hash_tests.cpp
#include <gtest/gtest.h>
#include "hash.hpp"
#include <string>
#include <vector>
#include <random>
#include <algorithm>

namespace 
{

    // Helper function to convert hex string to bytes
    std::vector<uint8_t> hexToBytes(const std::string &hex)
    {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2)
        {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

    // Helper function to convert bytes to hex string
    std::string bytesToHex(const std::vector<uint8_t> &bytes)
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t byte : bytes)
        {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }

    // Generate random bytes for testing
    std::vector<uint8_t> generateRandomBytes(size_t length)
    {
        std::vector<uint8_t> bytes(length);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        for (size_t i = 0; i < length; ++i)
        {
            bytes[i] = static_cast<uint8_t>(dis(gen));
        }
        return bytes;
    }

} // anonymous namespace

class HashTests : public ::testing::Test
{
protected:
    void SetUp() override
    {
        crypto::CryptoLogger::set_debug_mode(true);
    }

    void TearDown() override
    {
        crypto::CryptoLogger::set_debug_mode(false);
    }

    crypto::HashImpl hashImpl;
};

// NIST Test Vectors
// Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
TEST_F(HashTests, NISTTestVectors)
{
    // Test Vector #1
    {
        std::string input = "abc";
        std::string expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        auto result = hashImpl.sha256(std::vector<uint8_t>(input.begin(), input.end()));
        EXPECT_EQ(bytesToHex(result), expected);
    }

    // Test Vector #2
    {
        std::string input = "";
        std::string expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        auto result = hashImpl.sha256(std::vector<uint8_t>(input.begin(), input.end()));
        EXPECT_EQ(bytesToHex(result), expected);
    }

    // Test Vector #3
    {
        std::string input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        std::string expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
        auto result = hashImpl.sha256(std::vector<uint8_t>(input.begin(), input.end()));
        EXPECT_EQ(bytesToHex(result), expected);
    }
}

// Edge Cases
TEST_F(HashTests, EdgeCases)
{
    // Empty input
    {
        std::vector<uint8_t> empty;
        EXPECT_NO_THROW(hashImpl.sha256(empty));
    }

    // Single byte
    {
        std::vector<uint8_t> singleByte{0x00};
        EXPECT_NO_THROW(hashImpl.sha256(singleByte));
    }

    // 55 bytes (just under padding boundary)
    {
        std::vector<uint8_t> bytes(55, 0x61); // 'a'
        EXPECT_NO_THROW(hashImpl.sha256(bytes));
    }

    // 56 bytes (at padding boundary)
    {
        std::vector<uint8_t> bytes(56, 0x61);
        EXPECT_NO_THROW(hashImpl.sha256(bytes));
    }

    // 64 bytes (block size)
    {
        std::vector<uint8_t> bytes(64, 0x61);
        EXPECT_NO_THROW(hashImpl.sha256(bytes));
    }
}

// Input Validation
TEST_F(HashTests, InputValidation) {
    const std::vector<size_t> testSizes = {
        1024,       // 1 KB
        64 * 1024,  // 64 KB
        1024 * 1024 // 1 MB
    };

    for (size_t size : testSizes) {
        std::vector<uint8_t> input(size);
        crypto::CryptoLogger::debug("Testing input size: " + 
                                   std::to_string(size/1024) + "KB");
        
        auto start = std::chrono::high_resolution_clock::now();
        EXPECT_NO_THROW(hashImpl.sha256(input));
        auto end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        crypto::CryptoLogger::info("SHA-256 of " + std::to_string(size/1024) + 
                                  "KB completed in " + std::to_string(duration.count()) + "ms");
    }
}

// String Interface
TEST_F(HashTests, StringInterface)
{
    std::string input = "Hello, World!";
    auto stringResult = hashImpl.sha256(input);
    auto vectorResult = hashImpl.sha256(std::vector<uint8_t>(input.begin(), input.end()));
    EXPECT_EQ(stringResult, vectorResult);
}

// HMAC Tests
TEST_F(HashTests, HMACBasic)
{
    // Test Vector from RFC 4231
    std::vector<uint8_t> key = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    std::string message = "Hi There";
    std::vector<uint8_t> messageBytes(message.begin(), message.end());
    std::string expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

    auto result = hashImpl.hmacSha256(messageBytes, key);
    EXPECT_EQ(bytesToHex(result), expected);
}

TEST_F(HashTests, HMACEdgeCases)
{
    // Empty message
    {
        std::vector<uint8_t> key = generateRandomBytes(32);
        std::vector<uint8_t> emptyMessage;
        EXPECT_NO_THROW(hashImpl.hmacSha256(emptyMessage, key));
    }

    // Empty key
    {
        std::vector<uint8_t> emptyKey;
        std::vector<uint8_t> message = {0x01, 0x02, 0x03};
        EXPECT_NO_THROW(hashImpl.hmacSha256(message, emptyKey));
    }

    // Long key (should be hashed)
    {
        std::vector<uint8_t> longKey = generateRandomBytes(100);
        std::vector<uint8_t> message = {0x01, 0x02, 0x03};
        EXPECT_NO_THROW(hashImpl.hmacSha256(message, longKey));
    }
}

// Performance Tests
TEST_F(HashTests, LargeDataPerformance) {
    const std::vector<size_t> sizes = {
        1024,        // 1KB
        1024 * 1024  // 1MB
    };

    for (size_t size : sizes) {
        crypto::CryptoLogger::debug("Generating " + std::to_string(size/1024) + "KB of random data");
        std::vector<uint8_t> data = generateRandomBytes(size);

        crypto::CryptoLogger::debug("Starting hash computation");
        auto start = std::chrono::high_resolution_clock::now();
        auto hash = hashImpl.sha256(data);
        auto end = std::chrono::high_resolution_clock::now();

        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        crypto::CryptoLogger::info("SHA-256 of " + std::to_string(size/1024) + 
                                  "KB completed in " + std::to_string(duration.count()) + "ms");

        EXPECT_EQ(hash.size(), 32);
    }
}

// Consistency Tests
TEST_F(HashTests, ConsistentResults)
{
    // Test that multiple hashes of the same input produce the same result
    std::vector<uint8_t> input = generateRandomBytes(1000);

    auto hash1 = hashImpl.sha256(input);
    auto hash2 = hashImpl.sha256(input);
    auto hash3 = hashImpl.sha256(input);

    EXPECT_EQ(hash1, hash2);
    EXPECT_EQ(hash2, hash3);
}

// Million 'a' Test (from NIST test vectors)
TEST_F(HashTests, MillionA)
{
    std::string expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
    std::vector<uint8_t> input(1000000, 'a');

    auto result = hashImpl.sha256(input);
    EXPECT_EQ(bytesToHex(result), expected);
}