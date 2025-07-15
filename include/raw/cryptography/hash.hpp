#ifndef HASH_HPP
#define HASH_HPP

#include <vector>
#include <string>

namespace raw::cryptography::hash {

    std::vector<unsigned char> sha256(const std::string& data, const std::string& key);

}

#endif