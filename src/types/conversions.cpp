#include <raw/types/conversions.hpp>
#include <stdexcept>
#include <unordered_map>
#include <string>

#include <boost/json.hpp>

namespace raw::types::conversions {

    std::unordered_map<std::string, std::string> jsonStringToMap(const std::string& jsonString) {
        boost::system::error_code ec;
        boost::json::value val = boost::json::parse(jsonString, ec);
        if(ec) {
            throw std::runtime_error("JSON Parsing failed: " + ec.message());
        }

        if(!val.is_object()) {
            throw std::runtime_error("Invalid JSON object");
        }

        boost::json::object& obj = val.as_object();
        std::unordered_map<std::string, std::string> u_map;
        for(const auto& [key, val] : obj) {
            if(val.is_string()) {
                std::string copyKey(key);
                std::string copyVal(val.as_string().c_str());
                u_map.emplace(copyKey, copyVal);
            }
        }

        return u_map;
    }

    std::string mapToPrettyJsonString(const std::unordered_map<std::string, std::string>& jsonMap, const std::size_t indent) {
        std::ostringstream oss;
        oss << "{";

        if (!jsonMap.empty()) {
            oss << "\n";
            bool first = true;
            std::string indentStr(indent * 2, ' ');
            for (const auto& [key, val] : jsonMap) {
                if (!first) {
                    oss << ",\n";
                }
                first = false;
                oss << indentStr << "\"" << key << "\": \"" << val << "\"";
            }
            oss << "\n" << indentStr;
        }

        oss << "}";
        return oss.str();
        }

    std::string mapToJsonString(const std::unordered_map<std::string, std::string>& jsonMap) {
        return mapToPrettyJsonString(jsonMap, 0);
    }
}