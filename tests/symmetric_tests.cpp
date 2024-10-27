// symmetric_tests.cpp
#include <gtest/gtest.h>
#include "symmetric.hpp"
#include "crypto_logger.hpp"
#include <vector>
#include <algorithm>
#include <random>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>

namespace {
    std::string hexDump(const std::vector<uint8_t>& data, size_t max_bytes = 32) {
        std::stringstream ss;
        ss << "Size: " << data.size() << " bytes, Data: ";
        for (size_t i = 0; i < std::min(data.size(), max_bytes); ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(data[i]) << " ";
        }
        if (data.size() > max_bytes) ss << "...";
        return ss.str();
    }

    // Helper functions
    void createAESInstance(crypto::AESKeyLength keyLength) {
        crypto::ModernSymmetricImpl instance(keyLength);
    }

    std::vector<uint8_t> generateRandomData(size_t size) {
        std::vector<uint8_t> data(size);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        std::generate(data.begin(), data.end(), [&]() { return dis(gen); });
        return data;
    }

    std::vector<uint8_t> generateEdgeCaseData(size_t size, uint8_t value) {
        return std::vector<uint8_t>(size, value);
    }

    std::vector<uint8_t> generateSequentialData(size_t size) {
        std::vector<uint8_t> data(size);
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<uint8_t>(i % 256);
        }
        return data;
    }

    void verifyEncryptDecrypt(crypto::ModernSymmetricImpl& aes,
                            const std::vector<uint8_t>& plaintext,
                            const std::vector<uint8_t>& key,
                            const std::vector<uint8_t>& iv,
                            bool useIV = true) {
        std::cout << "\n[TEST] Original plaintext: " << hexDump(plaintext) << std::endl;
        std::cout << "[TEST] Key: " << hexDump(key) << std::endl;
        if (useIV) std::cout << "[TEST] IV: " << hexDump(iv) << std::endl;

        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> decrypted;

        try {
            if (useIV) {
                ciphertext = aes.aesEncryptCBC(plaintext, key, iv);
                std::cout << "[TEST] Ciphertext (CBC): " << hexDump(ciphertext) << std::endl;
                decrypted = aes.aesDecryptCBC(ciphertext, key, iv);
            } else {
                ciphertext = aes.aesEncryptECB(plaintext, key);
                std::cout << "[TEST] Ciphertext (ECB): " << hexDump(ciphertext) << std::endl;
                decrypted = aes.aesDecryptECB(ciphertext, key);
            }
            std::cout << "[TEST] Decrypted: " << hexDump(decrypted) << std::endl;

            if (plaintext.size() != decrypted.size()) {
                std::cout << "[TEST] Size mismatch! Plaintext: " << plaintext.size() 
                         << " bytes, Decrypted: " << decrypted.size() << " bytes" << std::endl;
                
                if (decrypted.size() > plaintext.size()) {
                    std::cout << "[TEST] Extra bytes: ";
                    for (size_t i = plaintext.size(); i < decrypted.size(); ++i) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                                 << static_cast<int>(decrypted[i]) << " ";
                    }
                    std::cout << std::endl;
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "[TEST] Exception during encryption/decryption: " 
                     << e.what() << std::endl;
            throw;
        }

        ASSERT_EQ(plaintext.size(), decrypted.size()) 
            << "Plaintext and decrypted sizes don't match";
        ASSERT_EQ(plaintext, decrypted) << "Decrypted data doesn't match original plaintext";
    }
}

// Base test fixture for shared functionality
class SymmetricTestBase : public ::testing::Test {
protected:
    void SetUp() override {
        crypto::CryptoLogger::set_debug_mode(true);
        std::cout << "[TEST] Test setup complete" << std::endl;
    }

    void TearDown() override {
        std::cout << "[TEST] Test teardown complete" << std::endl;
    }

    const size_t blockSize = 16; // AES block size
    crypto::ModernSymmetricImpl aes128{crypto::AESKeyLength::AES_128};
    crypto::ModernSymmetricImpl aes192{crypto::AESKeyLength::AES_192};
    crypto::ModernSymmetricImpl aes256{crypto::AESKeyLength::AES_256};
};

// Basic operation tests
class SymmetricTests : public SymmetricTestBase {};

TEST_F(SymmetricTests, KeySizeInitialization) {
    std::cout << "[TEST] Starting key size initialization tests" << std::endl;
    try {
        std::cout << "[TEST] Testing AES-128" << std::endl;
        createAESInstance(crypto::AESKeyLength::AES_128);

        std::cout << "[TEST] Testing AES-192" << std::endl;
        createAESInstance(crypto::AESKeyLength::AES_192);

        std::cout << "[TEST] Testing AES-256" << std::endl;
        createAESInstance(crypto::AESKeyLength::AES_256);
    } catch (const std::exception& e) {
        std::cerr << "[TEST] Unexpected exception: " << e.what() << std::endl;
        throw;
    }
    std::cout << "[TEST] Key size initialization tests complete" << std::endl;
}

TEST_F(SymmetricTests, ECBBasicOperation) {
    std::cout << "[TEST] Starting ECB basic operation test" << std::endl;
    std::vector<uint8_t> key = generateRandomData(16);
    std::vector<uint8_t> plaintext = generateRandomData(32); // Two blocks
    verifyEncryptDecrypt(aes128, plaintext, key, {}, false);
    std::cout << "[TEST] ECB basic operation test complete" << std::endl;
}

TEST_F(SymmetricTests, CBCBasicOperation) {
    std::cout << "[TEST] Starting CBC basic operation test" << std::endl;
    std::vector<uint8_t> key = generateRandomData(16);
    std::vector<uint8_t> iv = generateRandomData(16);
    std::vector<uint8_t> plaintext = generateRandomData(32);
    verifyEncryptDecrypt(aes128, plaintext, key, iv, true);
    std::cout << "[TEST] CBC basic operation test complete" << std::endl;
}

TEST_F(SymmetricTests, DifferentKeyLengths) {
    std::cout << "[TEST] Starting different key lengths test" << std::endl;
    std::vector<std::pair<crypto::AESKeyLength, crypto::ModernSymmetricImpl*>> implementations = {
        {crypto::AESKeyLength::AES_128, &aes128},
        {crypto::AESKeyLength::AES_192, &aes192},
        {crypto::AESKeyLength::AES_256, &aes256}
    };

    for (const auto& [keyLength, aes] : implementations) {
        std::cout << "[TEST] Testing key length: "
                  << static_cast<int>(keyLength) * 8 << " bits" << std::endl;
        size_t keySize = static_cast<size_t>(keyLength);
        std::vector<uint8_t> key = generateRandomData(keySize);
        std::vector<uint8_t> iv = generateRandomData(16);
        std::vector<uint8_t> plaintext = generateRandomData(32);
        verifyEncryptDecrypt(*aes, plaintext, key, iv);
    }
    std::cout << "[TEST] Different key lengths test complete" << std::endl;
}

// Edge case tests
class SymmetricEdgeCaseTests : public SymmetricTestBase {};

TEST_F(SymmetricEdgeCaseTests, EmptyInput) {
    std::vector<uint8_t> emptyData;
    std::vector<uint8_t> key(16, 0x00);
    std::vector<uint8_t> iv(16, 0x00);

    EXPECT_THROW(aes128.aesEncryptCBC(emptyData, key, iv), crypto::InvalidBlockSize);
    EXPECT_THROW(aes128.aesDecryptCBC(emptyData, key, iv), crypto::InvalidBlockSize);
}

TEST_F(SymmetricEdgeCaseTests, SingleBlockBoundary) {
    std::vector<uint8_t> data(blockSize, 0xAA);
    std::vector<uint8_t> key(16, 0x00);
    std::vector<uint8_t> iv(16, 0x00);

    auto encrypted = aes128.aesEncryptCBC(data, key, iv);
    EXPECT_EQ(encrypted.size(), 2 * blockSize); // One block + padding block
    
    auto decrypted = aes128.aesDecryptCBC(encrypted, key, iv);
    EXPECT_EQ(decrypted, data);
}

TEST_F(SymmetricEdgeCaseTests, NullBytePatterns) {
    std::vector<uint8_t> data(32, 0x00);
    std::vector<uint8_t> key(16, 0x00);
    std::vector<uint8_t> iv(16, 0x00);

    auto encrypted = aes128.aesEncryptCBC(data, key, iv);
    auto decrypted = aes128.aesDecryptCBC(encrypted, key, iv);
    EXPECT_EQ(decrypted, data);
}

TEST_F(SymmetricEdgeCaseTests, AllOnesPatterns) {
    std::vector<uint8_t> data(32, 0xFF);
    std::vector<uint8_t> key(16, 0xFF);
    std::vector<uint8_t> iv(16, 0xFF);

    auto encrypted = aes128.aesEncryptCBC(data, key, iv);
    auto decrypted = aes128.aesDecryptCBC(encrypted, key, iv);
    EXPECT_EQ(decrypted, data);
}

TEST_F(SymmetricEdgeCaseTests, AlternatingPatterns) {
    std::vector<uint8_t> data(32);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = (i % 2) ? 0xFF : 0x00;
    }
    std::vector<uint8_t> key(16, 0xAA);
    std::vector<uint8_t> iv(16, 0x55);

    auto encrypted = aes128.aesEncryptCBC(data, key, iv);
    auto decrypted = aes128.aesDecryptCBC(encrypted, key, iv);
    EXPECT_EQ(decrypted, data);
}

TEST_F(SymmetricEdgeCaseTests, LargeInputSize) {
    const size_t largeSize = 1024 * 1024; // 1MB
    std::vector<uint8_t> data = generateSequentialData(largeSize);
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> iv(16, 0x24);

    auto encrypted = aes128.aesEncryptCBC(data, key, iv);
    auto decrypted = aes128.aesDecryptCBC(encrypted, key, iv);
    EXPECT_EQ(decrypted, data);
}

TEST_F(SymmetricEdgeCaseTests, InvalidKeySizes) {
    std::vector<uint8_t> data(32, 0x42);
    std::vector<uint8_t> iv(16, 0x00);

    std::vector<uint8_t> shortKey(15, 0x00);  // Too short
    EXPECT_THROW(aes128.aesEncryptCBC(data, shortKey, iv), crypto::InvalidKeyLength);
    
    std::vector<uint8_t> longKey(33, 0x00);  // Too long
    EXPECT_THROW(aes128.aesEncryptCBC(data, longKey, iv), crypto::InvalidKeyLength);
}

TEST_F(SymmetricEdgeCaseTests, InvalidIVSizes) {
    std::vector<uint8_t> data(32, 0x42);
    std::vector<uint8_t> key(16, 0x00);

    std::vector<uint8_t> shortIV(15, 0x00);  // Too short
    EXPECT_THROW(aes128.aesEncryptCBC(data, key, shortIV), crypto::InvalidBlockSize);
    
    std::vector<uint8_t> longIV(17, 0x00);  // Too long
    EXPECT_THROW(aes128.aesEncryptCBC(data, key, longIV), crypto::InvalidBlockSize);
}

TEST_F(SymmetricEdgeCaseTests, PaddingEdgeCases) {
    std::vector<uint8_t> key(16, 0x00);
    std::vector<uint8_t> iv(16, 0x00);
    
    // Test all possible block-unaligned sizes
    for (size_t i = 1; i < blockSize; ++i) {
        std::vector<uint8_t> data(i, 0x42);
        auto encrypted = aes128.aesEncryptCBC(data, key, iv);
        auto decrypted = aes128.aesDecryptCBC(encrypted, key, iv);
        EXPECT_EQ(decrypted, data);
    }
}

TEST_F(SymmetricEdgeCaseTests, KeySchedulingVariations) {
    std::vector<uint8_t> data(32, 0x42);
    std::vector<uint8_t> iv(16, 0x00);

    // Test with different key patterns for each key size
    std::vector<uint8_t> key128(16, 0xAA);
    std::vector<uint8_t> key192(24, 0x55);
    std::vector<uint8_t> key256(32, 0x33);

    // Test 128-bit key
    auto encrypted128 = aes128.aesEncryptCBC(data, key128, iv);
    auto decrypted128 = aes128.aesDecryptCBC(encrypted128, key128, iv);
    EXPECT_EQ(decrypted128, data);

    // Test 192-bit key
    auto encrypted192 = aes192.aesEncryptCBC(data, key192, iv);
    auto decrypted192 = aes192.aesDecryptCBC(encrypted192, key192, iv);
    EXPECT_EQ(decrypted192, data);

    // Test 256-bit key
    auto encrypted256 = aes256.aesEncryptCBC(data, key256, iv);
    auto decrypted256 = aes256.aesDecryptCBC(encrypted256, key256, iv);
    EXPECT_EQ(decrypted256, data);
}

TEST_F(SymmetricEdgeCaseTests, CBCErrorPropagation) {
    std::vector<uint8_t> data(48, 0x42);  // 3 blocks
    std::vector<uint8_t> key(16, 0x00);
    std::vector<uint8_t> iv(16, 0x00);

    auto encrypted = aes128.aesEncryptCBC(data, key, iv);
    
    // Modify each block and verify decryption behavior
    for (size_t i = 0; i < encrypted.size(); i += blockSize) {
        auto modified = encrypted;
        modified[i] ^= 0xFF;  // Flip bits in one byte of each block
        
        auto decrypted = aes128.aesDecryptCBC(modified, key, iv);
        EXPECT_NE(decrypted, data);  // Ensure the error propagated
    }
}

int main(int argc, char **argv) {
    std::cout << "[TEST] Starting test suite" << std::endl;
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    std::cout << "[TEST] Test suite complete" << std::endl;
    return result;
}