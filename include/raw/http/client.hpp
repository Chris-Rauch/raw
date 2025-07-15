#ifndef CLIENT_HPP
#define CLIENT_HPP
#include <raw/http/token.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/basic_resolver_results.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/asio/ssl/verify_mode.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <cstdlib>
#include <string>
#include <unordered_map>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using stream = beast::ssl_stream<beast::tcp_stream>;
using response = http::response<http::dynamic_body>;
using tcp = net::ip::tcp;

namespace raw::http {

//TODO - Error handlign
class Client {
protected:
    /**
     * @brief Performs a DNS lookup an establishes a connection with the host.
     *   This is where the TLS handshake occurs. 
     * 
     * @param ctx A configured SSL context object.
     * @param host A host/domain name. Do not add prefixes (i.e. https) 
     * @param port The target port.
     * @param type Either client or server. Default to client.
     * @return stream 
     */
    stream connect_(
        ssl::context& ctx,
        const std::string& host,
        const std::string& port,
        const net::ssl::stream_base::handshake_type& type = net::ssl::stream_base::client
    );

    /**
     * @brief Before creating an encrypted stream, the class must construct an
     * SSL context object. SSL Context supports TLS. This function allows the
     * user to configure specific SSL/TLS settings. By default, the safest and
     * most generic options are chosen. 
     * 
     * @param method Sets encryption and authentication technique.
     *   sslv23 (default) will negotiate the highest security standard between
     *   server and client. Usually means TLS 1.0-1.3 with SSLv2/v3 disabled.
     *   See the following for more options: https://beta.boost.org/doc/libs/1_66_0/doc/html/boost_asio/reference/ssl__context/method.html
     * @param verifyMode Configures certificate verification method.
     *   verify_peer (default) Will verify the peer's certificate with
     *   'verifyFile'(see below). This is the safest option for clients, however
     *   different settings may be applicable if running as a server.
     * @param verifyFile File path as a string. This points to your system's
     *   certificate authority file. Default option is where the file normally
     *   is on linux. If unknown, change to blank string. This will force boost
     *   to try and find defaults.
     * @return ssl::context 
     */
    ssl::context createSSLContext_(
        const ssl::context::method& method = ssl::context::sslv23,
        const net::ssl::verify_mode& verifyMode = boost::asio::ssl::verify_peer,
        const std::string& verifyFile = "/etc/ssl/certs/ca-certificates.crt"
    ) const;


    /**
     * @brief Shuts down the SSL/TLS connection. If the beast::error code is
     *   empty then it shutdown gracefully.
     * 
     * @param stream The stream to shutdown.
     * @return beast::error_code 
     */
    beast::error_code disconnect_(
        beast::ssl_stream<beast::tcp_stream>& stream
    ) const;

    /**
     * @brief Processes input in a buffer from the stream object. Use responseAs
     *   functions for cleaner data handling.
     * 
     * @param stream The active stream connection.
     * @return response 
     */
    response receive_(beast::ssl_stream<beast::tcp_stream>& stream) const;

    /**
     * @brief Sends data across the active stream to the server.
     * 
     * @param stream An active stream object.
     * @param method GET, POST etc..
     * @param host Host name for the server. Note that this does nto include the
     *   endpoint.
     * @param target Endpoint/everything that comes after hostname i.e "/token"
     *   for oath.google.com/token
     * @param version HTTP header version number
     * @param headers Any additional custom headers. Defaulted to empty map
     * @param body Body as a string. User must handle formatting.
     */
    void request_(
        beast::ssl_stream<beast::tcp_stream>& stream,
        const beast::http::verb& method,
        const std::string& host,
        const std::string& target,
        int version,
        const std::unordered_map<std::string, std::string>& headers = {},
        const std::string& body = "" 
    ) const;

    // TODO - double check these functions
    std::vector<uint8_t> responseAsBytes_(const response& res) const ;
    std::string responseAsString_(const response& res) const;

protected:
    net::io_context ioc_;// core event loop. All network IO goes through here
    bool client_;
    bool host_;

};


class GoogleDrive : protected Client {
public:
    // constructors
    GoogleDrive();

    // request access token from Google OAuth 2.0 servers
    bool auth(const std::string& jwt);

    std::string getResponse() const {return response_;}
    std::string getOauth() const;

    std::vector<uint8_t> requestFile(
        const std::unordered_map<std::string, std::string>& header,
        const JSON& body,
        const std::string& fileId,
        const std::string& mimeType
    );

private:
    std::string file_uri_;
    std::string file_target_;
    std::string auth_uri_;
    std::string auth_target_;
    std::string port_;
    int version_;

    // state variables
    std::string response_;
};

} // namespace http


#endif