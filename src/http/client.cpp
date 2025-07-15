#include <raw/http/client.hpp>
#include <raw/http/token.hpp>
#include <raw/encode/encode.hpp>
#include <raw/types/conversions.hpp>
#include <boost/asio/ip/basic_resolver_results.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/stream_traits.hpp>
#include <boost/beast/http/dynamic_body.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/verb.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <iostream>
#include <vector>

// namespace
namespace beast = boost::beast;
namespace net = boost::asio;
namespace ssl = net::ssl;
using GoogleDrive = raw::http::GoogleDrive;
using tcp = net::ip::tcp;
using Client = raw::http::Client;

stream Client::connect_(
    ssl::context& ctx,
    const std::string& host,
    const std::string& port,
    const net::ssl::stream_base::handshake_type& type
) {
    // resolve host names
    tcp::resolver resolver(ioc_);
    auto result = resolver.resolve(host, port);

    // make connection
    stream str(ioc_, ctx);

    // include host name in tls handshake
    if (!SSL_set_tlsext_host_name(str.native_handle(), host.c_str())) {
        throw beast::system_error(
            beast::error_code(static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()),
            "Failed to set SNI hostname"
        );
    }

    beast::get_lowest_layer(str).connect(result);
    str.handshake(type);
    return str;
}

ssl::context Client::createSSLContext_(
    const ssl::context::method& method,
    const net::ssl::verify_mode& verifyMode,
    const std::string& verifyFile
) const {
    ssl::context ctx(method);

    // find certificate authority
    if(verifyFile.empty()) {
        ctx.set_default_verify_paths();
    }
    else {
        ctx.load_verify_file(verifyFile);
    }

    //verify
    ctx.set_verify_mode(verifyMode);
    return ctx;
}

beast::error_code Client::disconnect_(
    beast::ssl_stream<beast::tcp_stream>& stream
) const {
    // Shutdown SSL
    beast::error_code ec;
    stream.shutdown(ec);
    if (ec == net::error::eof || ec == net::ssl::error::stream_truncated) ec = {};
    return ec;
}

response Client::receive_(beast::ssl_stream<beast::tcp_stream>& stream) const {
    beast::flat_buffer buffer;
    response res;
    beast::http::read(stream, buffer, res);
    return res;
}

void Client::request_(
    beast::ssl_stream<beast::tcp_stream>& stream,
    const beast::http::verb& method,
    const std::string& host,
    const std::string& target,
    int version,
    const std::unordered_map<std::string, std::string>& headers,
    const std::string& body
) const {
    // Build HTTP request
    beast::http::request<beast::http::string_body> req{method, target, version};
    req.set(beast::http::field::host, host);
    req.set(beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    // Add custom headers
    for (const auto& [key, value] : headers) {
        req.set(key, value);
    }

    if(method == beast::http::verb::post) {
        req.body() = body;
        req.prepare_payload(); // Automatically sets Content-Length
    }

    // Send request
    beast::http::write(stream, req);

    std::cout << "Request: " << req << std::endl; //DEBUG
}

std::vector<uint8_t> Client::responseAsBytes_(const response& res) const{

    // treat the response as raw bytes and return
    auto buffers = res.body().data();
    std::vector<uint8_t> rawBytes;

    // Calculate total size of all buffers
    std::size_t totalSize = 0;
    for (auto buffer : buffers) {
        totalSize += buffer.size();
    }

    // Pre-allocate the vector
    rawBytes.reserve(totalSize);

    // Copy each buffer into the vector
    for (const auto& buffer : buffers) {
        const uint8_t* dataPtr = static_cast<const uint8_t*>(buffer.data());
        rawBytes.insert(rawBytes.end(), dataPtr, dataPtr + buffer.size());
    }

    return rawBytes;
}

std::string Client::responseAsString_(const response& res) const {
    std::string str;

    // count the data
    auto buffers = res.body().data();
    std::size_t size = 0;
    for(const auto buf : buffers) {
        size += buf.size();
    }

    // reserve the space
    str.reserve(size);

    // copy data from buffers into str
    for(const auto& buf : buffers) {
        const char* p = static_cast<const char*>(buf.data());
        str.insert(str.end(), p, p+ buf.size());
    }
    return str;
}

GoogleDrive::GoogleDrive() : 
    file_uri_("www.googleapis.com"),
    file_target_("/drive/v3/files/"),
    auth_uri_("oauth2.googleapis.com"), // I got DNS errors when prefixing with https
    auth_target_("/token"),
    port_("443"),
    version_(11),
    response_("") {}

bool GoogleDrive::auth(const std::string& jwt) {
    // establish connection
    ssl::context ctx = createSSLContext_();
    auto stream = connect_(ctx, auth_uri_, port_);

    // make request
    const auto action = beast::http::verb::post;
    const std::string kGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    const std::unordered_map<std::string, std::string> header = {
        {"Content-Type", "application/x-www-form-urlencoded"}
    };
    const JSON body = std::unordered_map<std::string, std::string>{
        {"grant_type", kGrantType},
        {"assertion", jwt}
    };

    request_(
        stream,
        action,
        auth_uri_,
        auth_target_,
        version_,
        header,
        raw::cryptography::encode::form_encode(body)
    );
    auto response = receive_(stream);

    // disconnect from SSL
    auto err = disconnect_(stream);
    if(err) {
        std::cout << "Stream did not shutdown properyl. EC: " + err.message() << std::endl;
    }

    // check for response
    response_ = responseAsString_(response);
    if(response_.empty() || response_.find("access_token") == std::string::npos) return false;
    return true;
}

std::vector<uint8_t> GoogleDrive::requestFile(
    const std::unordered_map<std::string, std::string>& header,
    const JSON& body,
    const std::string& fileId,
    const std::string& mimeType
) {
    // establish a connection
    ssl::context ctx = createSSLContext_();
    auto stream = connect_(ctx, file_uri_, port_);

    // make request
    std::string target = file_target_ + fileId + "/export?mimeType=" + mimeType;
    //std::string target = "www.googleapis.com/drive/v3/files/11Sl8zGK_llQaTM1aj2b_s6oMC6oRpa989lFrKWQepKY?fields=id,name,mimeType";
    request_(
        stream,
        beast::http::verb::get,
        file_uri_,
        target,
        version_,
        header
    );
    auto response = receive_(stream);

    // disconnect from SSL
    auto err = disconnect_(stream);
    if(err) {
        std::cout << "Stream did not shutdown properyl. EC: " + err.message() << std::endl;
    }

    return responseAsBytes_(response);
}

std::string GoogleDrive::getOauth() const {
    if(response_.empty()) {
        std::cerr << "Response is empty" <<std::endl;
        return "";
    }

    auto r = raw::types::conversions::jsonStringToMap(response_);
    if(auto search = r.find("access_token"); search == r.end()) {
        std::cerr << "Error finding access token" << std::endl;
        return "";
    }

    return r["access_token"];
}
