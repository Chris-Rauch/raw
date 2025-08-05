#include <raw/cryptography/encrypt.hpp>
#include <openssl/rsa.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/types.h>
#include <vector>
#include <filesystem>
#include <string>
#include <stdexcept>
#include <memory>
#include <fstream>


namespace raw::cryptography::encrypt {
    namespace rsa {
        using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
        using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
        
        std::vector<unsigned char> sha256(const std::string& data, EVP_PKEY* pkey) {
            EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
            if (!ctx) throw std::runtime_error("Failed to create EVP_MD_CTX.");

            if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
                throw std::runtime_error("EVP_DigestSignInit failed.");
            }

            if (EVP_DigestSignUpdate(ctx.get(), data.data(), data.size()) <= 0) {
                throw std::runtime_error("EVP_DigestSignUpdate failed.");
            }

            // Get required signature size
            size_t sigLen = 0;
            if (EVP_DigestSignFinal(ctx.get(), nullptr, &sigLen) <= 0) {
                throw std::runtime_error("EVP_DigestSignFinal (get length) failed.");
            }

            std::vector<unsigned char> signature(sigLen);

            if (EVP_DigestSignFinal(ctx.get(), signature.data(), &sigLen) <= 0) {
                throw std::runtime_error("EVP_DigestSignFinal failed.");
            }

            signature.resize(sigLen);
            return signature;
        }

        std::vector<unsigned char> sha256(const std::string& data, const std::string& key) {
            EVP_PKEY_ptr pkey(loadPrivateKeyFromString(key.data(), key.size()), EVP_PKEY_free);
            return sha256(data, pkey.get());
        }
        
        std::vector<unsigned char> sha256(const std::string& data, const std::filesystem::path& path) {
            EVP_PKEY_ptr pkey(loadPrivateKeyFromFile(path.c_str()), EVP_PKEY_free);
            return sha256(data, pkey.get());
        }



    } // namespace rsa

    namespace hmac {
        void sha256(const void* key, const int key_len, const unsigned char* data, const int data_len, unsigned char* out, unsigned int* out_len) {
            auto evp_md = EVP_sha256();
            auto result = *HMAC(
                evp_md, // use this hash function
                key, // use this key
                key_len,
                data, // start signing here
                data_len, //num bytes to sign
                out, // output
                out_len //output len
            );
            if (!result) throw std::runtime_error("HMAC computation failed");
        }

        std::vector<unsigned char> sha256(const std::string& data, const std::string& key) {
            unsigned int len = 32;
            unsigned char output[32];
            
            sha256(key.data(), key.size(), reinterpret_cast<const unsigned char*>(data.data()), data.size(), output, &len);
            return std::vector<unsigned char>(output,output + len);
        }

        std::vector<unsigned char> sha256(const std::string& data, const std::filesystem::path& path) {
            unsigned int out_len = 32;
            unsigned char output[32];
            std::ifstream inFile(path, std::ios::binary | std::ios::ate);
            if(!inFile.is_open()) {
                throw std::runtime_error("Unable to open HMAC key file");
            }
            auto buf = inFile.rdbuf();
            inFile.seekg(0, inFile.end);
            int file_len = inFile.tellg();
            inFile.seekg(0, inFile.beg);

            char* buffer = new char[file_len];
            if(!inFile.read(buffer, file_len)) {
                throw std::runtime_error("Failed to read HMAC key file");
            }
            sha256(buffer, file_len, reinterpret_cast<const unsigned char*>(data.data()), data.size(), output, &out_len);
            inFile.close();
            std::vector<unsigned char> return_data = {output, output+out_len};
            delete[] buffer;
            return return_data;
        }

    } // end hmac
    
    EVP_PKEY* loadPrivateKeyFromString(const char key[], const int len) {
        BIO* bio = BIO_new_mem_buf(key, len);
        if (!bio) {
            throw std::runtime_error("Failed to create BIO.");
        }

        EVP_PKEY* pKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pKey) {
            throw std::runtime_error("Failed to parse RSA private key.");
        }

        return pKey;
    }

    EVP_PKEY* loadPrivateKeyFromFile(const char* filePath) {
        // Open the PEM file
        FILE* file = fopen(filePath, "r");
        if (!file) {
            throw std::runtime_error("Unable to open private key file.");
        }

        // Read the key
        EVP_PKEY* pkey = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
        fclose(file);

        if (!pkey) {
            throw std::runtime_error("Failed to load private key from file.");
        }

        return pkey;
    }

} // namespace encrypt