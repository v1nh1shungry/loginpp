#include "client_factory.h"

#include <boost/algorithm/hex.hpp>
#include <boost/asio.hpp>
#include <boost/endian.hpp>
#include <boost/uuid/detail/md5.hpp>

#include <openssl/md5.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <iostream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

class PostgresqlClient final : public Client {
public:
  PostgresqlClient() : Client{5432} {}

protected:
  bool login_impl(const std::string &ip, const std::string &username,
                  const std::string &password) {
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::socket socket{io_context};
    boost::asio::ip::tcp::resolver resolver{io_context};
    boost::asio::connect(socket, resolver.resolve(ip, std::to_string(port_)));

    // send startup message
    std::string startup_msg;
    // protocol version
    // The most significant 16 bits are the major version number (3 for the
    // protocol described here). The least significant 16 bits are the minor
    // version number (0 for the protocol described here).
    int32_t version;
    reinterpret_cast<uint16_t *>(&version)[0] = 0;
    reinterpret_cast<uint16_t *>(&version)[1] = 3;
    boost::endian::native_to_big_inplace(version);
    std::copy(reinterpret_cast<char *>(&version),
              reinterpret_cast<char *>(&version) + sizeof(version),
              std::back_inserter(startup_msg));
    // username
    startup_msg += "user";
    startup_msg.push_back('\0');
    startup_msg += username;
    startup_msg.push_back('\0');
    // database (default to "postgres")
    startup_msg += "database";
    startup_msg.push_back('\0');
    startup_msg += "postgres";
    startup_msg.push_back('\0');
    // a zero byte is required as a terminator after the last name/value pair
    startup_msg.push_back('\0');
    int32_t startup_msg_length =
        boost::endian::native_to_big<int32_t>(startup_msg.size() + 4);
    boost::asio::write(socket, boost::asio::buffer(&startup_msg_length,
                                                   sizeof(startup_msg_length)));
    boost::asio::write(socket, boost::asio::buffer(startup_msg));

    // receive auth message
    int8_t flag;
    boost::asio::read(socket, boost::asio::buffer(&flag, sizeof(flag)));
    assert(flag == 'R');
    int32_t auth_msg_length;
    boost::asio::read(
        socket, boost::asio::buffer(&auth_msg_length, sizeof(auth_msg_length)));
    auth_msg_length = boost::endian::big_to_native(auth_msg_length) - 4;
    std::vector<char> auth_msg;
    auth_msg.resize(auth_msg_length);
    boost::asio::read(socket, boost::asio::buffer(auth_msg));
    int32_t auth_method;
    std::copy(auth_msg.begin(), auth_msg.begin() + sizeof(auth_method),
              reinterpret_cast<char *>(&auth_method));
    boost::endian::big_to_native_inplace(auth_method);
    // no need to auth
    if (auth_method == 0) {
      std::cout << "no password, login successfully" << std::endl;
      return true;
    } else if (auth_method != 5) {
      std::cerr << "unknown encrypt method: " << auth_method << std::endl;
      return false;
    }
    std::array<char, 4> salt;
    std::copy(auth_msg.begin() + 4, auth_msg.begin() + 8, salt.begin());
    // DEBUG
    std::cerr << "salt: ";
    for (char c : salt) {
      std::cerr << static_cast<int>(static_cast<unsigned char>(c)) << ' ';
    }
    std::cerr << std::endl;

    // send password
    // we only support MD5 for now
    //  pwdhash = md5(password + username).hexdigest()
    //  hash = 'md5' + md5(pwdhash + salt).hexdigest()
    // DEBUG
    std::cerr << "username: " << username << std::endl;
    std::cerr << "password: " << password << std::endl;
    std::array<char, MD5_DIGEST_LENGTH * 2> pwdhash;
    {
      // boost::uuids::detail::md5::digest_type digest;
      // boost::uuids::detail::md5 md5;
      // std::string data = password + username;
      // md5.process_bytes(data.c_str(), data.size());
      // md5.get_digest(digest);
      // boost::algorithm::hex_lower(reinterpret_cast<char *>(digest),
      //                             reinterpret_cast<char *>(digest) +
      //                                 sizeof(digest),
      //                             std::back_inserter(pwdhash));
      unsigned char digest[MD5_DIGEST_LENGTH];
      std::vector<char> data;
      std::copy(password.begin(), password.end(), std::back_inserter(data));
      std::copy(username.begin(), username.end(), std::back_inserter(data));
      MD5(reinterpret_cast<const unsigned char *>(data.data()), data.size(),
          digest);
      constexpr auto map = "0123456789abcdef";
      for (std::size_t i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        pwdhash[i * 2] = map[digest[i] / 16];
        pwdhash[i * 2 + 1] = map[digest[i] % 16];
      }
    }
    std::array<char, MD5_DIGEST_LENGTH * 2> hash;
    {
      // boost::uuids::detail::md5::digest_type digest;
      // boost::uuids::detail::md5 md5;
      // std::string data = pwdhash + salt.data();
      // md5.process_bytes(data.c_str(), data.size());
      // md5.get_digest(digest);
      // boost::algorithm::hex_lower(reinterpret_cast<char *>(digest),
      //                             reinterpret_cast<char *>(digest) +
      //                                 sizeof(digest),
      //                             std::back_inserter(hash));
      unsigned char digest[MD5_DIGEST_LENGTH];
      std::vector<char> data;
      std::copy(pwdhash.begin(), pwdhash.end(), std::back_inserter(data));
      std::copy(salt.begin(), salt.end(), std::back_inserter(data));
      MD5(reinterpret_cast<const unsigned char *>(data.data()), data.size(),
          digest);
      constexpr auto map = "0123456789abcdef";
      for (std::size_t i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        hash[i * 2] = map[digest[i] / 16];
        hash[i * 2 + 1] = map[digest[i] % 16];
      }
    }
    std::cerr << "encrypted password: ";
    for (char c : hash) {
      std::cerr << c;
    }
    std::cerr << std::endl;
    std::string password_msg;
    // message flag
    password_msg.push_back('p');
    int32_t password_msg_length =
        boost::endian::native_to_big<int32_t>(4 + 3 + hash.size() + 1);
    std::copy(reinterpret_cast<char *>(&password_msg_length),
              reinterpret_cast<char *>(&password_msg_length) +
                  sizeof(password_msg_length),
              std::back_inserter(password_msg));
    password_msg += "md5";
    std::copy(hash.begin(), hash.end(), std::back_inserter(password_msg));
    password_msg.push_back('\0');
    boost::asio::write(socket, boost::asio::buffer(password_msg));

    // receive auth response
    boost::asio::read(socket, boost::asio::buffer(&flag, sizeof(flag)));
    int32_t auth_response_length;
    boost::asio::read(socket,
                      boost::asio::buffer(&auth_response_length,
                                          sizeof(auth_response_length)));
    auth_response_length =
        boost::endian::big_to_native(auth_response_length) - 4;
    std::vector<char> auth_response;
    auth_response.resize(auth_response_length);
    boost::asio::read(socket, boost::asio::buffer(auth_response));
    assert(flag == 'R');
    int32_t status;
    std::copy(auth_response.begin(), auth_response.end(),
              reinterpret_cast<char *>(&status));
    boost::endian::big_to_native_inplace(status);
    if (status == 0) {
      std::cout << "login successfully" << std::endl;
      std::this_thread::sleep_for(std::chrono::seconds(10));
      return true;
    }
    std::cerr << "auth failed" << std::endl;
    return false;
  }
};

static bool registered = ClientFactory::register_client(
    "postgresql", []() -> std::unique_ptr<Client> {
      return std::make_unique<PostgresqlClient>();
    });
