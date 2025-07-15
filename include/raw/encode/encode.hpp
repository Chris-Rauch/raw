#ifndef ENCODE_HPP
#define ENCODE_HPP

#include <cstddef>
#include <string>
#include <sys/stat.h>
#include <type_traits>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/insert_linebreaks.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <unordered_map>

/**
 * @brief Encoding functions for data transfer.
 * 
 */
namespace raw::cryptography::encode {

	/**
     * @brief Base64 encode/decode the given memory location. 
     * 
     * @param data Pointer to memory block.
     * @param size Size in bytes. If input is a non-byte array, you must
     *   manually make the conversion to bytes.
     * @return std::string 
     */
	std::string base64_encode(const void* data, std::size_t size);
	std::string base64_decode(const void* data, std::size_t size);

	/**
	 * @brief 
	 * 
	 * @param data 
	 * @param size 
	 * @return std::string 
	 */
	std::string base64url_encode(const void* data, std::size_t size);
	std::string base64url_decode(const void* data, std::size_t size);

	/**
	 * @brief 
	 * 
	 * @return std::string
	 * @throws runtime_error Invalid form data
	 */
	std::string form_encode(const std::unordered_map<std::string, std::string>& map);
	std::string form_decode(const std::unordered_map<std::string, std::string>& map);

	/**
	 * @brief URL encode/decode. This is referencing percent encodings in URL
	 *   strings. If a character is not alpha numeric, -, _, ., or ~ then it is
	 *   converted percent ASCII hex string (i.e. a space character returns %20)
	 *   
	 * @note form flag is used for data transfer that follows
	 *   x-www-form-urlencoded format.
	 * 
	 * @param data Pointer to memory.
	 * @param size Number of bytes.
	 * @param form Flag to indicate whether the space character should be
	 *   encoded as %20 or +. 
	 * @return std::string 
	 */
	std::string url_encode(const void* data, std::size_t size, bool formEncode = false);
	std::string url_decode(const void* data, std::size_t size, bool formEncode = false);

	// === Template Definitions ================================================
	// =========================================================================
	
	/**
     * @brief Base64 encode the contents of the given object.
     *
     * @tparam T Any object that implements the following:
     *     1) data() - A dumb pointer to a contiguous memory location.
     *     2) size() - The number of elements.
     *
     * @param data A contiguous memory wrapper.
     * @return std::string 
     */
    template <typename T>
    std::string base64_encode(const T& data) {
        // ensure object implements .data() and .size()
        static_assert(
            std::is_convertible_v<decltype(data.data()), const void*> &&
            std::is_convertible_v<decltype(data.size()), std::size_t>,
            "T must implement .data() and .size() functions"
        );
        const void* ptr = static_cast<const void*>(data.data());
        std::size_t size = static_cast<std::size_t>(data.size()) * 
          sizeof(std::remove_pointer_t<decltype(data.data())>);
        return base64_encode(ptr, size);
    }

	/**
     * @brief Base64 encode the contents of the given object.
     *
     * @tparam T Any object that implements the following:
     *     1) data() - A dumb pointer to a contiguous memory location.
     *     2) size() - The number of elements.
     *
     * @param data A contiguous memory wrapper.
     * @return std::string 
     */
	template <typename T>
	std::string base64_decode(const T& data) {
		static_assert(
			std::is_convertible_v<decltype(data.data()), const void*> &&
			std::is_convertible_v<decltype(data.size()), std::size_t>,
			"T must implement .data( and .size() functions"
		);
		const void* ptr = static_cast<const void*>(data.data());
		std::size_t size = static_cast<std::size_t>(data.size()) * 
		  sizeof(std::remove_pointer_t<decltype(data.data())>);
		return base64_decode(ptr, size);
	}

	/**
     * @brief URL encode the contents of the given object.
	 *
	 * @note URL encoding refers to the percent encoding. If a character is not
	 *   alpha numeric, -, _, ., or ~ then it is converted percent ASCII hex
	 *   string (i.e. a space character returns %20).
     *
     * @tparam T Any object that implements the following:
     *     1) data() - A dumb pointer to a contiguous memory location.
     *     2) size() - The number of elements.
     *
     * @param data A contiguous memory wrapper.
     * @return std::string 
     */
	template <typename T>
	std::string url_encode(const T& data) {
		static_assert(
			std::is_convertible_v<decltype(data.data()), const void*> &&
			std::is_convertible_v<decltype(data.size()), std::size_t>,
		    "T must implement .data() and .size()" 
		);
		const void* ptr = static_cast<void*>(data.data());
		std::size_t size = static_cast<std::size_t>(data.size()) * 
		  sizeof(std::remove_pointer_t<decltype(data.data)>);
		return url_encode(ptr, size);
	}

	/**
     * @brief URL decode the contents of the given object.
     *
	 * @note URL decoding refers to the percent decoding. Looks for a percent
	 *   percent sign and if found convert the follwoing two hex digits to their
	 *   ASCII value.
	 *
     * @tparam T Any object that implements the following:
     *     1) data() - A dumb pointer to a contiguous memory location.
     *     2) size() - The number of elements.
     *
     * @param data A contiguous memory wrapper.
     * @return std::string 
     */
	template <typename T>
	std::string url_decode(const T& data) {
		static_assert(
			std::is_convertible_v<decltype(data.data()), const void*> &&
			std::is_convertible_v<decltype(data.size()), std::size_t>,
		    "T must implement .data() and .size()" 
		);
		const void* ptr = static_cast<void*>(data.data());
		std::size_t size = static_cast<std::size_t>(data.size()) * 
		  sizeof(std::remove_pointer_t<decltype(data.data)>);
		return url_decode(ptr, size);
	}

	/**
     * @brief Base64 URL encode the contents of the given object.
     *
     * @tparam T Any object that implements the following:
     *     1) data() - A dumb pointer to a contiguous memory location.
     *     2) size() - The number of elements.
     *
     * @param data A contiguous memory wrapper.
     * @return std::string 
     */
	template <typename T>
	std::string base64url_encode(const T& data) {
		std::string encoded = base64_encode(data);
		std::replace(encoded.begin(), encoded.end(), '+', '-');
		std::replace(encoded.begin(), encoded.end(), '/', '_');
		
		// strip padding
		while(!encoded.empty() && encoded.back() == '=') {
			encoded.pop_back();
		}
		return encoded;
	}

	/**
     * @brief Base64 URL decode the contents of the given object.
     *
     * @tparam T Any object that implements the following:
     *     1) data() - A dumb pointer to a contiguous memory location.
     *     2) size() - The number of elements.
     *
     * @param data A contiguous memory wrapper.
     * @return std::string 
     */
	template <typename T>
	std::string base64url_decode(const T& data) {
		static_assert(
			std::is_convertible_v<decltype(data.data()), const char*> &&
			std::is_convertible_v<decltype(data.size()), std::size_t>, 
		    "T must implement .data() and .size()" 
		);
		// convert to string
		std::string str(static_cast<const char*>(data.data()), data.size());

		std::replace(str.begin(), str.end(), '-', '+');
		std::replace(str.begin(), str.end(), '_', '/');
		return base64_decode(str.data(), str.size());
	}
}
 
#endif // ENCODE_HPP
