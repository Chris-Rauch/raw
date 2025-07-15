#include <raw/cryptography/encrypt.hpp>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/types.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <memory>


namespace raw::cryptography::encrypt {
    namespace rsa {
        using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
        using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
        
        /**
         * @brief RSA SHA256 signing algorithm using OpenSSL. If managing your
         *   own EVP_PKEY be sure to remember to use EVP_PKEY_free to avoid mem
         *   leaks.
         * 
         * @param data reference data to be signed
         * @param pkey OpenSSL Private Key object
         * @return std::vector<unsigned char> The signed data as bytes.
         */
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

        /**
         * @brief RSA SHA256 signing algorithm. Best use case if you only have
         *   have access to your private key as a string, rather than a file. 
         * 
         * @param data reference data to be signed
         * @param key full private key as a string (inlcude the --begin-- portion)
         * @return std::vector<unsigned char> 
         */
        std::vector<unsigned char> sha256(const std::string& data, const std::string& key) {
            EVP_PKEY_ptr pkey(loadPrivateKeyFromString(key.data(), key.size()), EVP_PKEY_free);
            return sha256(data, pkey.get());
        }

    } // namespace rsa
    
    /**
    * @brief Creates an OpenSSL private key object. The caller is
    *   responsible for releasing the key (EVP_PKEY_free) to avoid mem
    *   leaks.
    * 
    * @param key the private key.
    * @param len length of key
    * @return EVP_PKEY* OpenSSL private key object
    */
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

    /**
    * @brief Grab your private key from a file and return it as structured
    *   data.
    * 
    * @param filePath c string (null terminated) file path.
    * @return EVP_PKEY* OpenSSL private key object
    */
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