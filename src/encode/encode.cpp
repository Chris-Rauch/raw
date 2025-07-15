#include <raw/encode/encode.hpp>
#include <algorithm>
#include <cassert>
#include <cctype>
#include <cstddef>
#include <cstring>
#include <iomanip>
#include <ios>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/insert_linebreaks.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <unordered_map>

namespace raw::cryptography::encode {

    std::string base64_encode(const void* data, std::size_t size) {
        //line break defualt arg??
        using namespace boost::archive::iterators;

        // interpret memory location as a byte array
        const char* bytes = static_cast<const char*>(data);

        // boost lib iterator magic
        using base64Iterator = base64_from_binary<
            transform_width<const char*, 6, 8>
        >;
        
        // using the iterator, create the encoded string
        std::string encodedStr(
            base64Iterator(bytes),
            base64Iterator(bytes + size)
        );

        // add padding and return
        std::size_t r = size % 3;
        std::size_t paddCount = (r == 0) ? 0 : (3 - r);
        encodedStr.append(paddCount, '=');
        return encodedStr;
    }

    std::string base64_decode(const void* data, std::size_t size) {
        using namespace boost::archive::iterators;

        // interpret memory location as a byte array
        const char* bytes = static_cast<const char*>(data);

        // add padding if necessary
        const char* begin = bytes;
        std::size_t padSize = (4 - (size % 4)) % 4;
        std::string padded;
        if(padSize > 0) {
            padded.reserve(size+padSize);
            padded.assign(begin, size);
            padded.append(padSize, '=');
            begin = padded.data();
            size = padded.size();
        }

        // create iterator, decode and return
        using base64Iterator = transform_width<
          binary_from_base64<const char*>, 
          8,
          6
        >;

        return std::string(
            base64Iterator(begin),
            base64Iterator(begin+size)
        );
    }

    std::string url_encode(const void* data, std::size_t size, bool formEncode) {
        if(size == 0) return "";
        const char* bytes = static_cast<const char*>(data);

        std::ostringstream oss;
        oss << std::hex << std::uppercase; 
        
        for(std::size_t counter = 0; counter < size; ++counter) {
            unsigned char c = static_cast<unsigned char>(bytes[counter]);
            if(std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                oss << c;
            }
            else if(formEncode && c == ' ') {
                oss << '+';
            }
            else {
                oss << '%' << std::setw(2) << std::setfill('0') << static_cast<int>(c);
            }
        }
        return oss.str();
    }

    std::string url_decode(const void* data, std::size_t size, bool formEncode) {
        const char* bytes = static_cast<const char*>(data);
        std::string decoded;
        decoded.reserve(size);

        for (std::size_t i = 0; i < size; ++i) {
            if (bytes[i] == '%' && i + 2 < size) {
                char hex[3] = { bytes[i + 1], bytes[i + 2], '\0' };
                decoded.push_back(static_cast<char>(std::strtol(hex, nullptr, 16)));
                i += 2;
            } 
            else if(formEncode && bytes[i] == '+') {
                decoded.push_back(' ');
            } 
            else {
                decoded.push_back(bytes[i]);
            }
        }
        return decoded;
    }

    std::string base64url_encode(const void* data, std::size_t size) {
        std::string encoded = base64_encode(data, size);
        std::replace(encoded.begin(), encoded.end(), '+', '-');
        std::replace(encoded.begin(), encoded.end(), '/', '_');

        // strip padding
        while(!encoded.empty() && encoded.back() == '=') {
            encoded.pop_back();
        }
        return encoded;
    }

    std::string base64url_decode(const void* data, std::size_t size) {
        const char* ptr = static_cast<const char*>(data);
        std::string str(ptr, size);

        std::replace(str.begin(), str.end(), '-', '+');
        std::replace(str.begin(), str.end(), '_', '/');
        return base64_decode(str.data(), str.size());
    }

    std::string form_encode(const std::unordered_map<std::string, std::string>& map) {
        std::string str;
        for(const auto& [key, val] : map) {
            // each key and value need to be url safe
            std::string encodedKey = url_encode(key.data(), key.size(), true);
            std::string encodedVal = url_encode(val.data(), val.size(), true);

            // join with '=' and concatenate with '&'
            str.append(encodedKey + '=' + encodedVal + '&');
        }
        str.pop_back(); // remove the extra '&'
        return str;
    }

    std::unordered_map<std::string, std::string> form_decode(const std::string& data) {
        std::unordered_map<std::string, std::string> structData;
        std::size_t start = 0;

        while(start < data.size()) {
            std::size_t end = data.find('&', start);

            if(end == std::string::npos) {
                end = data.size();
            }

            std::string substr = data.substr(start, end - start);
            int a = substr.find('=');
            if(a != std::string::npos) {
                std::string key = url_decode(substr.substr(0, a).data(), a, true);
                std::string val = url_decode(substr.substr(a + 1).data(), substr.size() - (a + 1), true);
                structData[key] = val;
            }
            start = end + 1;
        }
        return structData;
    }
}
