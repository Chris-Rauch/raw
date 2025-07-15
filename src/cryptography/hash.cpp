#include <raw/cryptography/hash.hpp>
#include <openssl/sha.h>
#include <vector>

namespace raw::cryptography::encode {

    std::vector<unsigned char> sha256(const std::string& data, const std::string& key) {
        std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
        SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash.data());
        return hash;
    }

}