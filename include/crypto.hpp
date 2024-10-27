// crypto.hpp - Main library header
#pragma once

#include <memory>
#include <string>
#include <vector>

namespace crypto {

// Forward declarations of implementation classes
class ClassicalCipherImpl;
class ModernSymmetricImpl;
class AsymmetricImpl;
class HashFunctionImpl;
class DigitalSignatureImpl;
class KeyManagementImpl;
class MathUtilImpl;
class PrimeOperationsImpl;

class CryptoLib {
public:
    CryptoLib();
    ~CryptoLib();

    // Classical Ciphers Interface
    std::string caesarEncrypt(const std::string& plaintext, int shift);
    std::string caesarDecrypt(const std::string& ciphertext, int shift);
    std::string vigenereEncrypt(const std::string& plaintext, const std::string& key);
    std::string vigenereDecrypt(const std::string& ciphertext, const std::string& key);

    // Modern Symmetric Encryption Interface
    std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& data, 
                                   const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& iv);
    std::vector<uint8_t> aesDecrypt(const std::vector<uint8_t>& data,
                                   const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& iv);

    // Asymmetric Encryption Interface
    void generateRSAKeyPair(size_t keySize);
    std::vector<uint8_t> rsaEncrypt(const std::vector<uint8_t>& data);
    std::vector<uint8_t> rsaDecrypt(const std::vector<uint8_t>& data);

    // Hash Functions Interface
    std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
    std::vector<uint8_t> sha3(const std::vector<uint8_t>& data);

    // Digital Signatures Interface
    std::vector<uint8_t> signRSA(const std::vector<uint8_t>& data);
    bool verifyRSA(const std::vector<uint8_t>& data, 
                   const std::vector<uint8_t>& signature);

    // Key Management Interface
    std::vector<uint8_t> generateKey(size_t keySize);
    std::vector<uint8_t> deriveKey(const std::string& password, 
                                  const std::vector<uint8_t>& salt);

private:
    std::unique_ptr<ClassicalCipherImpl> classical_;
    std::unique_ptr<ModernSymmetricImpl> symmetric_;
    std::unique_ptr<AsymmetricImpl> asymmetric_;
    std::unique_ptr<HashFunctionImpl> hash_;
    std::unique_ptr<DigitalSignatureImpl> signature_;
    std::unique_ptr<KeyManagementImpl> keyMgmt_;
    std::unique_ptr<MathUtilImpl> mathUtil_;
    std::unique_ptr<PrimeOperationsImpl> primeOps_;
};

} // namespace crypto