#ifndef ENCRYPT_HPP
#define ENCRYPT_HPP
#include <filesystem>
#include <vector>
#include <string>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/sha.h>

namespace raw::cryptography::encrypt {

    namespace rsa {
        /**
         * @brief RSA SHA256 signing algorithm using OpenSSL. If managing your
         *   own EVP_PKEY be sure to remember to use EVP_PKEY_free to avoid mem
         *   leaks.
         * 
         * @param data reference data to be signed
         * @param key OpenSSL Private Key
         * @return std::vector<unsigned char> The signed data as bytes.
         */
        std::vector<unsigned char> sha256(const std::string& data, EVP_PKEY* key);

        /**
         * @brief RSA SHA256 signing algorithm. Key is a string in memory.
         * 
         * @param data reference data to be signed
         * @param key full private key as a string (inlcude the --begin-- portion)
         * @return std::vector<unsigned char> 
         *
         * @throw runtime_exception - failed to parse RSA private key.
         */
        std::vector<unsigned char> sha256(const std::string& data, const std::string& key);

        /**
         * @brief RSA SHA256 signing algorithm. Key is a file.
         * 
         * @param data reference data to be signed
         * @param key full private key as a string (inlcude the --begin-- portion)
         * @return std::vector<unsigned char> 
         *
         * @throw runtime_exception - failed to parse RSA private key.
         */
        std::vector<unsigned char> sha256(const std::string& data, const std::filesystem::path& path);

    }

    namespace hmac {
        void sha256(const void* key, const int key_len, const unsigned char* data, const int data_len, unsigned char* out, unsigned int* out_len); 
        std::vector<unsigned char> sha256(const std::string& data, const std::string& key);
    }
    
    /**
    * @brief Creates an OpenSSL private key object. The caller is
    *   responsible for releasing the key (EVP_PKEY_free) to avoid mem
    *   leaks.
    * 
    * @param key the private key.
    * @param len length of key
    * @return EVP_PKEY* OpenSSL private key object
    */
    EVP_PKEY* loadPrivateKeyFromString(const char key[], const int len);

    /**
    * @brief Grab your private key from a file and return it as structured
    *   data.
    * 
    * @param filePath c string (null terminated) file path.
    * @return EVP_PKEY* OpenSSL private key object
    */
    EVP_PKEY* loadPrivateKeyFromFile(const char* fileName);
}

#endif