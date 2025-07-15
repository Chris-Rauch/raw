#ifndef ENCRYPT_HPP
#define ENCRYPT_HPP
#include <vector>
#include <string>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/sha.h>

namespace raw::cryptography::encrypt {

    namespace rsa {
        std::vector<unsigned char> sha256(const std::string& data, const std::string& key);
        std::vector<unsigned char> sha256(const std::string& data, EVP_PKEY* key);
    }
    
    // key access
    EVP_PKEY* loadPrivateKeyFromString(const char key[], const int len);
    EVP_PKEY* loadPrivateKeyFromFile(const char* fileName);
}

#endif