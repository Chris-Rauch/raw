#include <raw/types/json.hpp>
#include <sstream>
#include <stdexcept>
#include <ostream>

using JSON = raw::types::JSON;

// Default constructor
JSON::JSON() = default;

// Constructor from unordered_map<string, string>
JSON::JSON(const std::unordered_map<std::string, std::string>& value)
    : map_(value) {}

// Serialize map_ to JSON string (no pretty print, no escaping)
std::string JSON::asString() const {
    return prettyPrint(0);
}

// Helper: indentation string
static std::string indentStr(int indent) {
    return std::string(indent * 2, ' ');
}

// Convert to JSON string with indentation
std::string JSON::prettyPrint(int indent) const {
    std::ostringstream oss;
    oss << "{";

    if (!map_.empty()) {
        oss << "\n";
        bool first = true;
        for (const auto& [key, val] : map_) {
            if (!first) {
                oss << ",\n";
            }
            first = false;
            oss << indentStr(indent + 1) << "\"" << key << "\": \"" << val << "\"";
        }
        oss << "\n" << indentStr(indent);
    }

    oss << "}";
    return oss.str();
}

// Access (non-const) for inserting/modifying values
std::string& JSON::operator[](const std::string& key) {
    return map_[key];
}

// Access (const) for reading values; throws if key not found
const std::string& JSON::operator[](const std::string& key) const {
    auto it = map_.find(key);
    if (it == map_.end()) {
        throw std::out_of_range("Key not found: " + key);
    }
    return it->second;
}

// Stub: parsing is not implemented yet
void JSON::parse(const std::string& jsonString) {
    // TODO: implement a real JSON parser or integrate a library
    throw std::runtime_error("parse() not implemented");
}


std::ostream& operator<<(std::ostream& os, const JSON& j) {
    const std::string out = j.asString();
    os << out;
    return os;
}
