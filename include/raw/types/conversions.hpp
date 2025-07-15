#ifndef CONVERSION_HPP
#define CONVERSION_HPP

#include <cstddef>
#include <unordered_map>
#include <string>

namespace raw::types::conversions {

    /**
     * @brief 
     * 
     * @note may fail to load some values silently. Due to have boost's
     *   is_string() function evaluates it's internal state.
     * 
     * @param jsonString 
     * @return std::unordered_map<std::string, std::string> 
     */
    std::unordered_map<std::string, std::string> jsonStringToMap(const std::string& jsonString);
    std::string mapToJsonString(const std::unordered_map<std::string, std::string>& jsonMap);
    std::string mapToPrettyJsonString(const std::unordered_map<std::string, std::string>& jsonMap, const std::size_t indent);
}

#endif