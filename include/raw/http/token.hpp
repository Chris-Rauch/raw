/**
 * @file token.h
 * @author Chris Rauch
 * @brief Container for a JSON Web Token. Allows the user to add headers, claims
 *   and sign the token. Handles UTF-8 serialization and Base64URL encoding.
 *
 * @version 0.1
 * @date 2025-07-04
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#ifndef TOKEN_HPP
#define TOKEN_HPP

#include <boost/json.hpp>

#include <string>
#include <unordered_map>

using JSON = std::unordered_map<std::string, std::string>;

namespace raw::http::token {

// Abstract Class
class Token {
public:
  // destructor
  virtual ~Token() = default;

  /**
   * @brief Create and return the fully formed token as a string. This includes
   *   token signature and proper encoding. Ready for transmission.
   * 
   * @param alg Cryptographic algorithm to sign the token.
   * @param key Private key to sign the data.
   * @return std::string 
   */
  virtual std::string token(const std::string& alg = "", const std::string& key = "") const = 0;

  /**
   * @brief Sign token and return just the signature.
   * 
   * @param alg Cryptographic algorithm to sign the token.
   * @param key Private key to sign the data.
   * @return std::string 
   */
  virtual std::string sign(const std::string& alg, const std::string& key) = 0;

  /**
   * @brief Converts token string back into structured data. Overwrites any 
   *   existing data.
   * 
   * @param token Token as a string.
   */
  virtual void parse(const std::string& token) = 0;

  /**
   * @brief Verify the signature using the given algorithm and public key.
   * 
   * @param alg Signing algorithm
   * @param key Public key
   * @return true If the signature is valid and not expired.
   * @return false If the signature check failed or token is expired.
   */
  virtual bool verify(const std::string& alg, const std::string& key) = 0;

protected:
  virtual bool isExpired() const = 0;
  virtual bool isValid() const = 0;
};

class JWT: public Token {
public:
  JWT() {}
  JWT(const JSON& header, const JSON& claims, const std::string& sig = "") :
      header_(header), claims_(claims), signature_(sig) {}

  void appendHeader(const std::string& key, const std::string& val); 
  void appendHeader(const JSON& header); 

  void appendClaim(const std::string& key, const std::string& val); 
  void appendClaim(const JSON& claim); 

  void parse(const std::string& token);

  /**
  * @brief Creates a base64 URL encoded signature based on the header and claims
  *   portions of the token. Will overwrite the current signature, if there is
  *   one.
  * 
  * @param alg Signing algorithm. 
  * @param pKey Private key as a string.
  * @return std::string 
  */
  std::string sign(const std::string& alg, const std::string& pkey);
  std::string token(const std::string& alg, const std::string& pkey) const;
  bool verify(const std::string& alg, const std::string& key); // TODO

private:
  bool isExpired() const; //TODO
  bool isValid() const; //TODO

private:
  JSON header_;
  JSON claims_;
  std::string signature_;
};
  
} // namespace token
#endif
