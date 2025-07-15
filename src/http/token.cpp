#include <raw/cryptography/hash.hpp>
#include <raw/encode/encode.hpp>
#include <raw/cryptography/encrypt.hpp>
#include <raw/http//token.hpp>
#include <raw/types/conversions.hpp>
#include <stdexcept>
#include <string>
#include <unordered_map>

using JWT = raw::http::token::JWT;

void JWT::appendClaim(const std::string& key, const std::string& val) {
  claims_[key] = val;
}

void JWT::appendClaim(const JSON& header) {

  //TODO 
  throw std::runtime_error("Function appendClaim is not yet implemented");
}

void JWT::appendHeader(const std::string& key, const std::string& val) {
    header_[key] = val;
}

void JWT::appendHeader(const JSON& header) {
  //TODO 
  throw std::runtime_error("Function appendHeader is not yet implemented");
}

void JWT::parse(const std::string& token) {
    int firstDot = token.find_first_of('.');
    int secondDot = token.find_last_of('.');

    // still encoded
    std::string header_e = token.substr(0,firstDot);
    std::string claims_e = token.substr(firstDot + 1,secondDot - firstDot - 1);
    std::string signat_e = token.substr(secondDot + 1);

    std::string header = raw::cryptography::encode::base64url_decode(header_e);
    std::string claims = raw::cryptography::encode::base64url_decode(claims_e);

    signature_ = raw::cryptography::encode::base64url_decode(signat_e);
    header_ = raw::types::conversions::jsonStringToMap(header);
    claims_ = raw::types::conversions::jsonStringToMap(claims);
}


std::string JWT::sign(const std::string& alg, const std::string& pKey) {
  std::vector<unsigned char> signature;

  // convert the json/map object into a string
  std::string header = raw::types::conversions::mapToJsonString(header_);
  std::string claims = raw::types::conversions::mapToJsonString(claims_);

  // encode the strings and concatenate
  std::string encodedHeader = raw::cryptography::encode::base64url_encode(header);
  std::string encodedClaims = raw::cryptography::encode::base64url_encode(claims);
  std::string payload = encodedHeader + '.' + encodedClaims;

  // sign
  if(alg == "RS256") {
    // hash and sign
    signature = raw::cryptography::encrypt::rsa::sha256(payload, pKey);
  }
  else {
    throw std::invalid_argument("Unsupported hashing algorith: " + alg);
  }

  auto encodedSignature = raw::cryptography::encode::base64url_encode(signature);
  std::string signatureStr(signature.begin(), signature.end());
  return this->signature_;
}

/* Returns a complete JWT with UTF-8 serialization and Base64Url encoded.
 *
*/
std::string JWT::token(const std::string& alg = "", const std::string& pkey = "") const {
  std::vector<unsigned char> signature;

  // convert the json/map object into a string
  std::string header = raw::types::conversions::mapToJsonString(header_);
  std::string claims = raw::types::conversions::mapToJsonString(claims_);

  // encode the strings and concatenate
  std::string encodedHeader = raw::cryptography::encode::base64url_encode(header);
  std::string encodedClaims = raw::cryptography::encode::base64url_encode(claims);
  std::string payload = encodedHeader + '.' + encodedClaims;

  // hash and sign
  signature = raw::cryptography::encrypt::rsa::sha256(payload, pkey);

  std::string signatureStr(signature.begin(), signature.end());

  return encodedHeader + '.' + encodedClaims + '.' + raw::cryptography::encode::base64url_encode(signatureStr);
}
bool JWT::verify(const std::string& alg, const std::string& key) {
  throw std::runtime_error("Verify token not implemented");
}
bool JWT::isExpired() const {return true;}
bool JWT::isValid() const {return false;}