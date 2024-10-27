// classical.hpp
#pragma once

#include <string>
#include <vector>

namespace crypto {

class ClassicalCipherImpl {
public:
    ClassicalCipherImpl() = default;
    ~ClassicalCipherImpl() = default;

    // Caesar Cipher
    std::string caesarEncrypt(const std::string& plaintext, int shift);
    std::string caesarDecrypt(const std::string& ciphertext, int shift);

    // Vigenère Cipher
    std::string vigenereEncrypt(const std::string& plaintext, const std::string& key);
    std::string vigenereDecrypt(const std::string& ciphertext, const std::string& key);

private:
    // Helper functions
    char shiftChar(char c, int shift, bool encrypt);
    std::string preprocessKey(const std::string& key, size_t messageLength);
};

// classical.cpp
#include "classical.hpp"
#include <algorithm>
#include <cctype>

namespace crypto {

std::string ClassicalCipherImpl::caesarEncrypt(const std::string& plaintext, int shift) {
    std::string result;
    shift = ((shift % 26) + 26) % 26; // Normalize shift to 0-25 range
    
    for (char c : plaintext) {
        result += shiftChar(c, shift, true);
    }
    return result;
}

std::string ClassicalCipherImpl::caesarDecrypt(const std::string& ciphertext, int shift) {
    std::string result;
    shift = ((shift % 26) + 26) % 26; // Normalize shift to 0-25 range
    
    for (char c : ciphertext) {
        result += shiftChar(c, shift, false);
    }
    return result;
}

std::string ClassicalCipherImpl::vigenereEncrypt(const std::string& plaintext, const std::string& key) {
    std::string processedKey = preprocessKey(key, plaintext.length());
    std::string result;
    
    for (size_t i = 0; i < plaintext.length(); ++i) {
        if (std::isalpha(plaintext[i])) {
            int shift = processedKey[i] - 'A';
            result += shiftChar(plaintext[i], shift, true);
        } else {
            result += plaintext[i];
        }
    }
    return result;
}

std::string ClassicalCipherImpl::vigenereDecrypt(const std::string& ciphertext, const std::string& key) {
    std::string processedKey = preprocessKey(key, ciphertext.length());
    std::string result;
    
    for (size_t i = 0; i < ciphertext.length(); ++i) {
        if (std::isalpha(ciphertext[i])) {
            int shift = processedKey[i] - 'A';
            result += shiftChar(ciphertext[i], shift, false);
        } else {
            result += ciphertext[i];
        }
    }
    return result;
}

char ClassicalCipherImpl::shiftChar(char c, int shift, bool encrypt) {
    if (!std::isalpha(c)) return c;
    
    char base = std::isupper(c) ? 'A' : 'a';
    if (encrypt) {
        return base + ((c - base + shift) % 26);
    } else {
        return base + ((c - base - shift + 26) % 26);
    }
}

std::string ClassicalCipherImpl::preprocessKey(const std::string& key, size_t messageLength) {
    std::string processedKey;
    std::string upperKey = key;
    
    // Convert key to uppercase
    std::transform(upperKey.begin(), upperKey.end(), upperKey.begin(), ::toupper);
    
    // Remove non-alphabetic characters
    upperKey.erase(
        std::remove_if(upperKey.begin(), upperKey.end(), 
                      [](char c) { return !std::isalpha(c); }),
        upperKey.end()
    );
    
    // Repeat key to match message length
    while (processedKey.length() < messageLength) {
        processedKey += upperKey;
    }
    processedKey = processedKey.substr(0, messageLength);
    
    return processedKey;
}

} // namespace crypto