/**
 * @file json.hpp
 * @author your name (you@domain.com)
 * @brief I just want a data structure that acts like a python dictionary, ya know.
 * @version 0.1
 * @date 2025-07-07
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#ifndef JSON_HPP
#define JSON_HPP

#include <string>
#include <unordered_map>

namespace raw::types {

class JSON {
public:
    // Constructors
    JSON();
    JSON(const std::unordered_map<std::string, std::string>& value);

    // convert
    std::string asString() const;
    std::string prettyPrint(int indent = 0) const;

    // load values
    void parse(const std::string& jsonString);

    // accesses
    bool empty() const {return map_.empty();}

    // operator overload
    std::string& operator[](const std::string& key);
    const std::string& operator[](const std::string& key) const;

    friend std::ostream& operator<<(std::ostream& os, const JSON& j);

private:
    std::unordered_map<std::string, std::string> map_;
};
}
#endif // JSON_HPP