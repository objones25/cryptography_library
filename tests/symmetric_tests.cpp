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
#include <thread>
#include <mutex>
#include <atomic>
#include <numeric>
#include <chrono>
#include <functional>
#include <future>
#include <cmath>

// Platform-specific headers
#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#elif defined(__APPLE__)
#include <mach/mach.h>
#include <mach/task.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#else
#include <sys/sysinfo.h>
#include <unistd.h>
#endif

namespace
{

    // Memory safety wrapper for sensitive data
    template <typename T>
    class SecureVector
    {
    private:
        std::vector<T> data;

    public:
        explicit SecureVector(size_t size) : data(size) {}
        ~SecureVector()
        {
            std::fill(data.begin(), data.end(), T{});
            data.clear();
        }

        std::vector<T> &get() { return data; }
        const std::vector<T> &get() const { return data; }
    };

    // Thread-safe counter for parallel operations
    class ThreadSafeCounter
    {
    private:
        std::atomic<size_t> value{0};

    public:
        void increment() { ++value; }
        size_t get() const { return value.load(); }
    };

    // Performance metrics structure
    struct PerformanceMetrics
    {
        double encryptionTime;
        double decryptionTime;
        double throughputMBps;
        size_t dataSize;
        size_t memoryUsage;

        std::string toString() const
        {
            std::stringstream ss;
            ss << "Data size: " << (dataSize / 1024.0 / 1024.0) << " MB\n"
               << "Encryption time: " << std::fixed << std::setprecision(3)
               << encryptionTime * 1000 << " ms\n"
               << "Decryption time: " << decryptionTime * 1000 << " ms\n"
               << "Throughput: " << std::fixed << std::setprecision(2)
               << throughputMBps << " MB/s\n"
               << "Memory usage: " << (memoryUsage / 1024.0 / 1024.0) << " MB";
            return ss.str();
        }
    };

    // Block-level metrics structure
    struct BlockMetrics
    {
        double processingTime;
        size_t bytesProcessed;
        double memoryUsed;
        bool success;
        std::string errorMessage;

        BlockMetrics() : processingTime(0), bytesProcessed(0),
                         memoryUsed(0), success(true) {}
    };

// Platform-specific memory measurement
#if defined(_WIN32)
    size_t getCurrentRSS()
    {
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
        {
            return pmc.WorkingSetSize;
        }
        return 0;
    }
#elif defined(__APPLE__)
    size_t getCurrentRSS()
    {
        struct mach_task_basic_info info;
        mach_msg_type_number_t infoCount = MACH_TASK_BASIC_INFO_COUNT;
        if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                      (task_info_t)&info, &infoCount) == KERN_SUCCESS)
        {
            return info.resident_size;
        }
        return 0;
    }
#else
    size_t getCurrentRSS()
    {
        FILE *fp = fopen("/proc/self/statm", "r");
        if (fp)
        {
            long rss = 0;
            if (fscanf(fp, "%*s%ld", &rss) == 1)
            {
                fclose(fp);
                return rss * sysconf(_SC_PAGESIZE);
            }
            fclose(fp);
        }
        return 0;
    }
#endif

    // Helper functions
    std::string hexDump(const std::vector<uint8_t> &data, size_t max_bytes = 32)
    {
        std::stringstream ss;
        ss << "Size: " << data.size() << " bytes, Data: ";
        for (size_t i = 0; i < std::min(data.size(), max_bytes); ++i)
        {
            ss << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<int>(data[i]) << " ";
        }
        if (data.size() > max_bytes)
            ss << "...";
        return ss.str();
    }

    std::vector<uint8_t> generateRandomData(size_t size)
    {
        std::vector<uint8_t> data(size);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        std::generate(data.begin(), data.end(),
                      [&]()
                      { return static_cast<uint8_t>(dis(gen)); });
        return data;
    }

    std::vector<uint8_t> generateSequentialData(size_t size)
    {
        std::vector<uint8_t> data(size);
        for (size_t i = 0; i < size; ++i)
        {
            data[i] = static_cast<uint8_t>(i % 256);
        }
        return data;
    }

    double calculateEntropy(const std::vector<uint8_t> &data)
    {
        if (data.empty())
            return 0.0;

        std::array<size_t, 256> histogram{};
        for (uint8_t byte : data)
        {
            histogram[byte]++;
        }

        double entropy = 0.0;
        for (size_t count : histogram)
        {
            if (count > 0)
            {
                double p = static_cast<double>(count) / data.size();
                entropy -= p * std::log2(p);
            }
        }
        return entropy;
    }

} // anonymous namespace

// Base test fixture
class SymmetricTestBase : public ::testing::Test
{
protected:
    void SetUp() override
    {
        crypto::CryptoLogger::set_debug_mode(true);
        startTime = std::chrono::high_resolution_clock::now();
        startRSS = getCurrentRSS();
    }

    void TearDown() override
    {
        auto endTime = std::chrono::high_resolution_clock::now();
        auto endRSS = getCurrentRSS();

        auto duration = std::chrono::duration<double>(endTime - startTime).count();
        auto memoryDelta = endRSS - startRSS;

        std::cout << "\nTest metrics:"
                  << "\nDuration: " << std::fixed << std::setprecision(3)
                  << duration << "s"
                  << "\nMemory delta: " << (memoryDelta / 1024.0 / 1024.0)
                  << " MB\n";
    }

    const size_t blockSize = 16;
    crypto::ModernSymmetricImpl aes128{crypto::AESKeyLength::AES_128};
    crypto::ModernSymmetricImpl aes192{crypto::AESKeyLength::AES_192};
    crypto::ModernSymmetricImpl aes256{crypto::AESKeyLength::AES_256};

private:
    std::chrono::high_resolution_clock::time_point startTime;
    size_t startRSS;

protected:
    // Enhanced verification function
    void verifyEncryptDecrypt(
        crypto::ModernSymmetricImpl &aes,
        const std::vector<uint8_t> &plaintext,
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &iv,
        bool useIV = true)
    {

        std::cout << "\n[TEST] Original plaintext: " << hexDump(plaintext) << std::endl;
        std::cout << "[TEST] Key: " << hexDump(key) << std::endl;
        if (useIV)
        {
            std::cout << "[TEST] IV: " << hexDump(iv) << std::endl;
        }

        try
        {
            std::vector<uint8_t> ciphertext;
            std::vector<uint8_t> decrypted;

            // Measure encryption performance
            auto encStart = std::chrono::high_resolution_clock::now();
            if (useIV)
            {
                ciphertext = aes.aesEncryptCBC(plaintext, key, iv);
                std::cout << "[TEST] Ciphertext (CBC): " << hexDump(ciphertext) << std::endl;
            }
            else
            {
                ciphertext = aes.aesEncryptECB(plaintext, key);
                std::cout << "[TEST] Ciphertext (ECB): " << hexDump(ciphertext) << std::endl;
            }
            auto encEnd = std::chrono::high_resolution_clock::now();

            // Verify ciphertext properties
            EXPECT_FALSE(ciphertext.empty()) << "Encryption produced empty ciphertext";
            EXPECT_EQ(ciphertext.size() % blockSize, 0)
                << "Ciphertext size not aligned to block size";

            // Check entropy of ciphertext
            double entropy = calculateEntropy(ciphertext);
            EXPECT_GT(entropy, 7.5)
                << "Ciphertext entropy too low: " << entropy;

            // Measure decryption performance
            auto decStart = std::chrono::high_resolution_clock::now();
            if (useIV)
            {
                decrypted = aes.aesDecryptCBC(ciphertext, key, iv);
            }
            else
            {
                decrypted = aes.aesDecryptECB(ciphertext, key);
            }
            auto decEnd = std::chrono::high_resolution_clock::now();

            // Verify results
            ASSERT_EQ(plaintext.size(), decrypted.size())
                << "Plaintext and decrypted sizes don't match";
            ASSERT_EQ(plaintext, decrypted)
                << "Decrypted data doesn't match original plaintext";

            // Log performance metrics
            auto encTime = std::chrono::duration<double>(encEnd - encStart).count();
            auto decTime = std::chrono::duration<double>(decEnd - decStart).count();

            std::cout << "[TEST] Performance metrics:\n"
                      << "  Encryption time: " << std::fixed << std::setprecision(3)
                      << encTime * 1000 << " ms\n"
                      << "  Decryption time: " << decTime * 1000 << " ms\n"
                      << "  Total time: " << (encTime + decTime) * 1000 << " ms\n";
        }
        catch (const std::exception &e)
        {
            ADD_FAILURE() << "Exception during encryption/decryption: " << e.what();
            throw;
        }
    }

    // Performance measurement function
    PerformanceMetrics measurePerformance(
        const std::vector<uint8_t> &data,
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &iv,
        crypto::ModernSymmetricImpl &impl)
    {

        PerformanceMetrics metrics;
        metrics.dataSize = data.size();
        size_t initialRSS = getCurrentRSS();

        try
        {
            auto start = std::chrono::high_resolution_clock::now();
            auto encrypted = impl.aesEncryptCBC(data, key, iv);
            auto encryptEnd = std::chrono::high_resolution_clock::now();

            auto decrypted = impl.aesDecryptCBC(encrypted, key, iv);
            auto end = std::chrono::high_resolution_clock::now();

            // Verify correctness
            EXPECT_EQ(data, decrypted);
            EXPECT_EQ(encrypted.size() % blockSize, 0);

            // Calculate metrics
            metrics.encryptionTime =
                std::chrono::duration<double>(encryptEnd - start).count();
            metrics.decryptionTime =
                std::chrono::duration<double>(end - encryptEnd).count();

            double totalBytes = static_cast<double>(data.size());
            double totalTime = metrics.encryptionTime + metrics.decryptionTime;
            metrics.throughputMBps = (totalBytes / (1024 * 1024)) / totalTime;

            // Measure memory impact
            size_t finalRSS = getCurrentRSS();
            metrics.memoryUsage = finalRSS - initialRSS;

            return metrics;
        }
        catch (const std::exception &e)
        {
            ADD_FAILURE() << "Performance measurement failed: " << e.what();
            throw;
        }
    }

    // Block-level performance measurement
    BlockMetrics measureBlockPerformance(
        const std::vector<uint8_t> &block,
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &iv)
    {

        BlockMetrics metrics;
        metrics.bytesProcessed = block.size();
        size_t initialRSS = getCurrentRSS();

        try
        {
            auto start = std::chrono::high_resolution_clock::now();

            auto encrypted = aes128.aesEncryptCBC(block, key, iv);
            auto decrypted = aes128.aesDecryptCBC(encrypted, key, iv);

            auto end = std::chrono::high_resolution_clock::now();

            if (block != decrypted)
            {
                metrics.success = false;
                metrics.errorMessage = "Decryption mismatch";
                return metrics;
            }

            metrics.processingTime =
                std::chrono::duration<double>(end - start).count();
            metrics.memoryUsed = getCurrentRSS() - initialRSS;
            metrics.success = true;

            return metrics;
        }
        catch (const std::exception &e)
        {
            metrics.success = false;
            metrics.errorMessage = e.what();
            return metrics;
        }
    }
};

TEST_F(SymmetricTestBase, BasicEncryptionDecryption)
{
    std::vector<uint8_t> data = generateRandomData(1024); // 1KB
    std::vector<uint8_t> key = generateRandomData(16);
    std::vector<uint8_t> iv = generateRandomData(16);

    auto encrypted = aes128.aesEncryptCBC(data, key, iv);
    auto decrypted = aes128.aesDecryptCBC(encrypted, key, iv);

    EXPECT_EQ(data, decrypted) << "Decrypted data doesn't match original";
}

TEST_F(SymmetricTestBase, SequentialDataPatterns)
{
    // Test with sequential data to verify no patterns leak through
    const size_t testSize = 1024;
    std::vector<uint8_t> key = generateRandomData(16);
    std::vector<uint8_t> iv = generateRandomData(16);

    auto seqData = generateSequentialData(testSize);
    auto encrypted = aes128.aesEncryptCBC(seqData, key, iv);

    // Check entropy of encrypted sequential data
    double entropy = calculateEntropy(encrypted);
    EXPECT_GT(entropy, 7.5) << "Low entropy in encrypted sequential data";

    auto decrypted = aes128.aesDecryptCBC(encrypted, key, iv);
    EXPECT_EQ(seqData, decrypted) << "Sequential data encryption/decryption failed";
}

TEST_F(SymmetricTestBase, MultipleBlockSizes)
{
    const std::vector<size_t> testSizes = {16, 32, 48, 64, 128, 256};
    std::vector<uint8_t> key = generateRandomData(16);
    std::vector<uint8_t> iv = generateRandomData(16);

    for (size_t size : testSizes)
    {
        std::vector<uint8_t> data = generateRandomData(size);

        auto encrypted = aes128.aesEncryptCBC(data, key, iv);
        auto decrypted = aes128.aesDecryptCBC(encrypted, key, iv);

        EXPECT_EQ(data, decrypted) << "Failed for size " << size;
    }
}

TEST_F(SymmetricTestBase, PaddingVerification)
{
    // Test case 1: Empty vector
    std::vector<uint8_t> empty;
    std::vector<uint8_t> key = generateRandomData(16);
    std::vector<uint8_t> iv = generateRandomData(16);

    auto encrypted1 = aes128.aesEncryptCBC(empty, key, iv);
    EXPECT_EQ(encrypted1.size(), 16); // One full block for padding only
    auto decrypted1 = aes128.aesDecryptCBC(encrypted1, key, iv);
    EXPECT_EQ(decrypted1, empty);

    // Test case 2: One byte
    std::vector<uint8_t> oneByte = {0x42};
    auto encrypted2 = aes128.aesEncryptCBC(oneByte, key, iv);
    EXPECT_EQ(encrypted2.size(), 16); // One full block
    auto decrypted2 = aes128.aesDecryptCBC(encrypted2, key, iv);
    EXPECT_EQ(decrypted2, oneByte);

    // Test case 3: Full block
    std::vector<uint8_t> fullBlock(16, 0x42);
    auto encrypted3 = aes128.aesEncryptCBC(fullBlock, key, iv);
    EXPECT_EQ(encrypted3.size(), 32); // Two full blocks (original + padding)
    auto decrypted3 = aes128.aesDecryptCBC(encrypted3, key, iv);
    EXPECT_EQ(decrypted3, fullBlock);

    // Test case 4: Block + 1 byte to verify padding works across blocks
    std::vector<uint8_t> blockPlusOne(17, 0x42);
    auto encrypted4 = aes128.aesEncryptCBC(blockPlusOne, key, iv);
    EXPECT_EQ(encrypted4.size(), 32); // Should round up to two full blocks
    auto decrypted4 = aes128.aesDecryptCBC(encrypted4, key, iv);
    EXPECT_EQ(decrypted4, blockPlusOne);
}

TEST_F(SymmetricTestBase, PaddingAlignment)
{
    std::vector<uint8_t> key = generateRandomData(16);
    std::vector<uint8_t> iv = generateRandomData(16);

    // Test all possible unaligned sizes up to 2 blocks
    for (size_t size = 0; size <= 32; size++)
    {
        std::vector<uint8_t> data(size, 0x42);
        auto encrypted = aes128.aesEncryptCBC(data, key, iv);

        // Verify encrypted size is properly aligned
        EXPECT_EQ(encrypted.size() % 16, 0)
            << "Size " << size << " produced unaligned output";
        EXPECT_EQ(encrypted.size(), ((size + 15) / 16) * 16)
            << "Size " << size << " produced incorrect padding";

        auto decrypted = aes128.aesDecryptCBC(encrypted, key, iv);
        EXPECT_EQ(decrypted, data)
            << "Size " << size << " failed to roundtrip";
    }
}

// Performance tests
class SymmetricPerformanceTests : public SymmetricTestBase
{
protected:
    void SetUp() override
    {
        SymmetricTestBase::SetUp();
        crypto::CryptoLogger::set_debug_mode(false);
    }
};

TEST_F(SymmetricPerformanceTests, LargeDataPerformance)
{
    const std::vector<size_t> testSizes = {
        64 * 1024,       // 64 KB
        1024 * 1024,     // 1 MB
        10 * 1024 * 1024 // 10 MB
    };

    // Define appropriate key sizes for each AES variant
    struct AESImplementation
    {
        std::string name;
        crypto::ModernSymmetricImpl *impl;
        size_t keySize;
    };

    std::vector<AESImplementation> implementations = {
        {"AES-128", &aes128, 16},
        {"AES-192", &aes192, 24},
        {"AES-256", &aes256, 32}};

    std::vector<uint8_t> iv = generateRandomData(16);

    for (size_t size : testSizes)
    {
        std::vector<uint8_t> data = generateRandomData(size);

        for (const auto &impl : implementations)
        {
            // Generate key of appropriate length for each implementation
            std::vector<uint8_t> key = generateRandomData(impl.keySize);

            auto metrics = measurePerformance(data, key, iv, *impl.impl);

            std::cout << impl.name << ":\n"
                      << metrics.toString() << "\n\n";

            // More realistic performance expectations
            EXPECT_LT(metrics.encryptionTime, 10.0)
                << impl.name << " encryption took too long";
            EXPECT_LT(metrics.decryptionTime, 10.0)
                << impl.name << " decryption took too long";
            EXPECT_GT(metrics.throughputMBps, 1.0)
                << impl.name << " throughput too low";
            EXPECT_LT(metrics.memoryUsage, size * 4)
                << impl.name << " memory usage too high";
        }
    }
}

TEST_F(SymmetricPerformanceTests, ParallelProcessing)
{
    const size_t dataSize = 5 * 1024 * 1024; // 5 MB
    const std::vector<int> threadCounts = {2, 4, 8};

    std::vector<uint8_t> key = generateRandomData(16);
    std::vector<uint8_t> iv = generateRandomData(16);
    std::vector<uint8_t> data = generateRandomData(dataSize);

    std::cout << "\nParallel Processing Results:" << std::endl;
    std::cout << "-------------------------" << std::endl;

    for (int numThreads : threadCounts)
    {
        auto startTime = std::chrono::high_resolution_clock::now();
        std::vector<std::future<BlockMetrics>> futures;
        std::vector<BlockMetrics> results;
        size_t blockSize = dataSize / numThreads;

        // Launch threads
        for (int i = 0; i < numThreads; ++i)
        {
            size_t start = i * blockSize;
            size_t end = (i == numThreads - 1) ? dataSize : (i + 1) * blockSize;

            std::vector<uint8_t> block(data.begin() + start, data.begin() + end);
            futures.push_back(std::async(std::launch::async,
                                         [this, block, key, iv]()
                                         {
                                             return measureBlockPerformance(block, key, iv);
                                         }));
        }

        // Collect results
        bool allSucceeded = true;
        double totalTime = 0;
        double totalBytes = 0;

        for (auto &future : futures)
        {
            auto result = future.get();
            if (!result.success)
            {
                allSucceeded = false;
                std::cout << "Thread failed: " << result.errorMessage << std::endl;
                continue;
            }
            totalTime += result.processingTime;
            totalBytes += result.bytesProcessed;
            results.push_back(std::move(result));
        }

        auto endTime = std::chrono::high_resolution_clock::now();
        double elapsed = std::chrono::duration<double>(endTime - startTime).count();
        double throughput = (totalBytes / (1024.0 * 1024.0)) / elapsed;

        std::cout << "Threads: " << numThreads << "\n"
                  << "Total throughput: " << std::fixed << std::setprecision(2)
                  << throughput << " MB/s\n"
                  << "Average thread time: " << (totalTime / numThreads) * 1000 << " ms\n"
                  << "Average thread throughput: " << (throughput / numThreads)
                  << " MB/s\n\n";

        EXPECT_TRUE(allSucceeded) << "Some threads failed";
        EXPECT_GT(throughput, 50.0 * numThreads)
            << "Parallel throughput too low for " << numThreads << " threads";
    }
}

TEST_F(SymmetricPerformanceTests, ProcessingTimeConsistency)
{
    const size_t numIterations = 100;
    const size_t blockSize = 16 * 1024; // 16KB blocks
    std::vector<uint8_t> data = generateRandomData(blockSize);
    std::vector<uint8_t> key = generateRandomData(16);
    std::vector<uint8_t> iv = generateRandomData(16);

    std::vector<double> processingTimes;
    processingTimes.reserve(numIterations);

    for (size_t i = 0; i < numIterations; ++i)
    {
        auto metrics = measureBlockPerformance(data, key, iv);
        EXPECT_TRUE(metrics.success);
        processingTimes.push_back(metrics.processingTime);
    }

    // Calculate statistics
    double avgTime = std::accumulate(processingTimes.begin(),
                                     processingTimes.end(), 0.0) /
                     numIterations;
    double variance = 0.0;
    double maxDeviation = 0.0;

    for (double time : processingTimes)
    {
        double deviation = std::abs(time - avgTime) / avgTime;
        maxDeviation = std::max(maxDeviation, deviation);
        variance += (time - avgTime) * (time - avgTime);
    }
    variance /= numIterations;
    double stdDev = std::sqrt(variance);

    std::cout << "Processing Time Statistics:\n"
              << "  Average: " << std::fixed << std::setprecision(3)
              << avgTime * 1000 << " ms\n"
              << "  Std Dev: " << stdDev * 1000 << " ms\n"
              << "  Max Deviation: " << std::fixed << std::setprecision(1)
              << maxDeviation * 100 << "%\n";

    EXPECT_LT(maxDeviation, 0.15);
    EXPECT_LT(stdDev / avgTime, 0.1);
}

// Edge case tests
class SymmetricEdgeCaseTests : public SymmetricTestBase
{
protected:
    void SetUp() override
    {
        SymmetricTestBase::SetUp();
        crypto::CryptoLogger::set_debug_mode(true);
    }
};

TEST_F(SymmetricEdgeCaseTests, PaddingEdgeCases)
{
    std::vector<uint8_t> key = generateRandomData(16);
    std::vector<uint8_t> iv = generateRandomData(16);

    // Test all possible block-unaligned sizes
    for (size_t i = 1; i < blockSize * 2; ++i)
    {
        std::vector<uint8_t> data = generateRandomData(i);

        auto encrypted = aes128.aesEncryptCBC(data, key, iv);
        EXPECT_EQ(encrypted.size() % blockSize, 0);

        auto decrypted = aes128.aesDecryptCBC(encrypted, key, iv);
        EXPECT_EQ(data, decrypted);
    }
}

TEST_F(SymmetricEdgeCaseTests, ErrorPropagation)
{
    const size_t dataSize = 64; // 4 blocks
    std::vector<uint8_t> data = generateRandomData(dataSize);
    std::vector<uint8_t> key = generateRandomData(16);
    std::vector<uint8_t> iv = generateRandomData(16);

    auto encrypted = aes128.aesEncryptCBC(data, key, iv);

    // Test error propagation at different positions
    for (size_t pos = 0; pos < encrypted.size(); pos += blockSize)
    {
        std::cout << "\nTesting error propagation at position " << pos << std::endl;

        // Create copy and modify one byte
        auto modified = encrypted;
        modified[pos] ^= 0xFF;

        auto decrypted = aes128.aesDecryptCBC(modified, key, iv);

        // Calculate and verify error propagation
        size_t changedBlocks = 0;
        size_t affectedBytes = 0;

        for (size_t i = 0; i < data.size(); i++)
        {
            if (data[i] != decrypted[i])
            {
                affectedBytes++;
                changedBlocks = (i / blockSize) + 1;
            }
        }

        std::cout << "Error propagation results:\n"
                  << "  Changed blocks: " << changedBlocks << "\n"
                  << "  Affected bytes: " << affectedBytes << std::endl;

        // Verify CBC error propagation properties
        if (pos == 0)
        {
            // First block error should affect all blocks due to CBC chaining
            EXPECT_GE(changedBlocks, dataSize / blockSize)
                << "First block error didn't propagate properly";
            EXPECT_GE(affectedBytes, data.size() / 2)
                << "First block error didn't affect enough bytes";
        }
        else
        {
            // Other block errors should affect current and next block
            EXPECT_GE(changedBlocks, 2)
                << "Error didn't affect minimum expected blocks";
            EXPECT_GE(affectedBytes, blockSize)
                << "Error didn't affect minimum expected bytes";
        }
    }
}

TEST_F(SymmetricEdgeCaseTests, MemoryBoundary)
{
    const std::vector<size_t> testSizes = {
        4096 - 1,  // Just under page size
        4096,      // At page size
        4096 + 1,  // Just over page size
        8192 - 16, // Just under two pages minus a block
        8192,      // Two pages
        8192 + 16  // Two pages plus a block
    };

    std::vector<uint8_t> key = generateRandomData(16);
    std::vector<uint8_t> iv = generateRandomData(16);

    for (size_t size : testSizes)
    {
        std::vector<uint8_t> data = generateRandomData(size);
        size_t initialRSS = getCurrentRSS();

        auto encrypted = aes128.aesEncryptCBC(data, key, iv);
        auto decrypted = aes128.aesDecryptCBC(encrypted, key, iv);

        size_t memoryOverhead = getCurrentRSS() - initialRSS;

        EXPECT_EQ(decrypted, data);
        EXPECT_LT(memoryOverhead, size * 3);
    }
}

// Memory and thread safety tests
class SymmetricSafetyTests : public SymmetricTestBase
{
protected:
    void SetUp() override
    {
        SymmetricTestBase::SetUp();
        crypto::CryptoLogger::set_debug_mode(false);
    }
};

TEST_F(SymmetricSafetyTests, MemoryLeakCheck)
{
    const size_t iterations = 1000;
    const size_t dataSize = 1024 * 1024; // 1MB
    std::vector<uint8_t> key = generateRandomData(16);
    std::vector<uint8_t> iv = generateRandomData(16);

    size_t initialRSS = getCurrentRSS();
    std::vector<size_t> memoryUsage;
    memoryUsage.reserve(iterations / 10);

    for (size_t i = 0; i < iterations; ++i)
    {
        std::vector<uint8_t> data = generateRandomData(dataSize);

        auto encrypted = aes128.aesEncryptCBC(data, key, iv);
        auto decrypted = aes128.aesDecryptCBC(encrypted, key, iv);

        if (i % 10 == 0)
        {
            size_t currentRSS = getCurrentRSS();
            memoryUsage.push_back(currentRSS - initialRSS);
        }
    }

    // Check for memory growth pattern
    bool hasLeak = false;
    if (memoryUsage.size() > 10)
    {
        size_t earlyAvg = std::accumulate(memoryUsage.begin(),
                                          memoryUsage.begin() + 5, 0ull) /
                          5;
        size_t lateAvg = std::accumulate(memoryUsage.end() - 5,
                                         memoryUsage.end(), 0ull) /
                         5;
        hasLeak = (lateAvg > earlyAvg * 1.5);
    }

    EXPECT_FALSE(hasLeak);
}

TEST_F(SymmetricSafetyTests, ThreadSafetyConcurrent)
{
    const size_t numThreads = 8;
    const size_t operationsPerThread = 100;
    std::atomic<bool> startFlag{false};
    std::vector<std::thread> threads;
    ThreadSafeCounter successCount, failureCount;

    // Shared encryption instance
    crypto::ModernSymmetricImpl sharedAes{crypto::AESKeyLength::AES_128};

    // Create and start threads
    for (size_t i = 0; i < numThreads; ++i)
    {
        threads.emplace_back([&]()
                             {
            while (!startFlag) {
                std::this_thread::yield();
            }

            std::vector<uint8_t> threadKey = generateRandomData(16);
            std::vector<uint8_t> threadIV = generateRandomData(16);

            for (size_t j = 0; j < operationsPerThread; ++j) {
                try {
                    std::vector<uint8_t> data = generateRandomData(1024);
                    auto encrypted = sharedAes.aesEncryptCBC(data, threadKey, threadIV);
                    auto decrypted = sharedAes.aesDecryptCBC(encrypted, threadKey, threadIV);

                    if (data == decrypted) {
                        successCount.increment();
                    } else {
                        failureCount.increment();
                    }
                }
                catch (const std::exception&) {
                    failureCount.increment();
                }
            } });
    }

    startFlag = true;

    for (auto &thread : threads)
    {
        thread.join();
    }

    size_t totalOperations = numThreads * operationsPerThread;
    EXPECT_EQ(successCount.get() + failureCount.get(), totalOperations);
    EXPECT_EQ(failureCount.get(), 0);
}

TEST_F(SymmetricSafetyTests, SecureErasure)
{
    const size_t dataSize = 1024 * 1024; // 1MB
    SecureVector<uint8_t> key(16);
    SecureVector<uint8_t> iv(16);

    std::generate(key.get().begin(), key.get().end(), []()
                  { return 0x42; });
    std::generate(iv.get().begin(), iv.get().end(), []()
                  { return 0x24; });

    // Fill with recognizable pattern
    std::vector<uint8_t> data(dataSize);
    std::iota(data.begin(), data.end(), 0);

    // Perform encryption
    auto encrypted = aes128.aesEncryptCBC(data, key.get(), iv.get());

    // Key and IV should be securely erased when SecureVector goes out of scope
    key.get().clear();
    iv.get().clear();

    // Memory contents should be overwritten
    for (const auto &byte : key.get())
    {
        EXPECT_EQ(byte, 0);
    }
    for (const auto &byte : iv.get())
    {
        EXPECT_EQ(byte, 0);
    }
}

#include <gtest/gtest.h>
#include "symmetric.hpp"
#include <vector>

class PKCS7PaddingTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        crypto::CryptoLogger::set_debug_mode(true);
    }

    crypto::ModernSymmetricImpl aes{crypto::AESKeyLength::AES_128};

    // Helper to check if padding is valid PKCS7
    bool isValidPKCS7Padding(const std::vector<uint8_t> &data)
    {
        if (data.empty())
            return false;

        uint8_t paddingLen = data.back();
        if (paddingLen == 0 || paddingLen > 16 || paddingLen > data.size())
        {
            crypto::CryptoLogger::debug("Invalid padding length: " +
                                        std::to_string(paddingLen));
            return false;
        }

        // Check all padding bytes are correct
        for (size_t i = data.size() - paddingLen; i < data.size(); i++)
        {
            if (data[i] != paddingLen)
            {
                crypto::CryptoLogger::debug("Invalid padding byte at position " +
                                            std::to_string(i) + ": " + std::to_string(data[i]));
                return false;
            }
        }
        return true;
    }

    // Helper to create test vectors with known padding
    std::vector<uint8_t> createTestVector(size_t dataSize)
    {
        std::vector<uint8_t> data(dataSize);
        // Fill with incrementing values
        for (size_t i = 0; i < dataSize; i++)
        {
            data[i] = static_cast<uint8_t>(i & 0xFF);
        }
        return data;
    }
};

TEST_F(PKCS7PaddingTest, SingleBlockWithPadding)
{
    // Test with 10 bytes of data (requires 6 bytes padding)
    std::vector<uint8_t> input = createTestVector(10);
    std::vector<uint8_t> key(16, 0x42); // Fixed key for reproducibility
    std::vector<uint8_t> iv(16, 0x24);  // Fixed IV for reproducibility

    crypto::CryptoLogger::debug("Original input: " + hexDump(input));

    // Encrypt (should add 6 bytes of padding)
    auto encrypted = aes.aesEncryptCBC(input, key, iv);
    crypto::CryptoLogger::debug("Encrypted data: " + hexDump(encrypted));
    ASSERT_EQ(encrypted.size(), 16); // Should be one full block

    // Decrypt
    auto decrypted = aes.aesDecryptCBC(encrypted, key, iv);
    crypto::CryptoLogger::debug("Decrypted data: " + hexDump(decrypted));

    // Verify original data matches
    ASSERT_EQ(decrypted.size(), input.size());
    EXPECT_EQ(decrypted, input);
}

TEST_F(PKCS7PaddingTest, FullBlockPadding)
{
    // Test with exactly 16 bytes (requires full block of padding)
    std::vector<uint8_t> input = createTestVector(16);
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> iv(16, 0x24);

    crypto::CryptoLogger::debug("Original input: " + hexDump(input));

    // Encrypt (should add full block of padding)
    auto encrypted = aes.aesEncryptCBC(input, key, iv);
    crypto::CryptoLogger::debug("Encrypted data: " + hexDump(encrypted));
    ASSERT_EQ(encrypted.size(), 32); // Should be two full blocks

    // Decrypt
    auto decrypted = aes.aesDecryptCBC(encrypted, key, iv);
    crypto::CryptoLogger::debug("Decrypted data: " + hexDump(decrypted));

    // Verify original data matches
    ASSERT_EQ(decrypted.size(), input.size());
    EXPECT_EQ(decrypted, input);
}

TEST_F(PKCS7PaddingTest, MultipleBlocksWithPadding)
{
    // Test with 30 bytes (spans 2 blocks, requires 2 bytes padding)
    std::vector<uint8_t> input = createTestVector(30);
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> iv(16, 0x24);

    crypto::CryptoLogger::debug("Original input: " + hexDump(input));

    // Encrypt
    auto encrypted = aes.aesEncryptCBC(input, key, iv);
    crypto::CryptoLogger::debug("Encrypted data: " + hexDump(encrypted));
    ASSERT_EQ(encrypted.size(), 32); // Should round up to 2 full blocks

    // Verify padding before decryption
    auto paddedSize = ((input.size() + 15) / 16) * 16;
    ASSERT_EQ(encrypted.size(), paddedSize);

    // Decrypt
    auto decrypted = aes.aesDecryptCBC(encrypted, key, iv);
    crypto::CryptoLogger::debug("Decrypted data: " + hexDump(decrypted));

    // Verify original data matches
    ASSERT_EQ(decrypted.size(), input.size());
    EXPECT_EQ(decrypted, input);
}

TEST_F(PKCS7PaddingTest, CorruptPadding)
{
    // Create initial valid data
    std::vector<uint8_t> input = createTestVector(10);
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> iv(16, 0x24);

    auto encrypted = aes.aesEncryptCBC(input, key, iv);
    crypto::CryptoLogger::debug("Original encrypted data: " + hexDump(encrypted));

    // Corrupt last byte (padding length)
    auto corrupted = encrypted;
    corrupted.back() ^= 0x01; // Flip one bit
    crypto::CryptoLogger::debug("Corrupted padding length: " + hexDump(corrupted));

    // Should throw on invalid padding
    EXPECT_THROW(aes.aesDecryptCBC(corrupted, key, iv), crypto::AESException);

    // Corrupt padding byte
    corrupted = encrypted;
    corrupted[corrupted.size() - 2] ^= 0x01; // Corrupt second-to-last byte
    crypto::CryptoLogger::debug("Corrupted padding byte: " + hexDump(corrupted));

    // Should throw on invalid padding
    EXPECT_THROW(aes.aesDecryptCBC(corrupted, key, iv), crypto::AESException);
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);

    // Add the custom test listener
    testing::TestEventListeners &listeners =
        testing::UnitTest::GetInstance()->listeners();
    listeners.Append(new testing::EmptyTestEventListener);

    return RUN_ALL_TESTS();
}