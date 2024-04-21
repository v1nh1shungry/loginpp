#include "client_factory.h"

#include <boost/asio.hpp>

#include <algorithm>
#include <iostream>
#include <iterator>
#include <string>
#include <thread>

class RedisClient final : public Client {
public:
  RedisClient() : Client{6379} {}

protected:
  bool login_impl(const std::string &ip, const std::string &,
                  const std::string &password) {
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::socket socket{io_context};
    boost::asio::ip::tcp::resolver resolver{io_context};
    boost::asio::connect(socket, resolver.resolve(ip, std::to_string(port_)));

    // send ping command to check if it is neccessary to auth
    // '*' stands for an array, '$' stands for a string
    // the following message means the command is consist of one string,
    // the string is 4 bytes long
    // each part is seperated by "\r\n"
    const std::string ping_msg = "*1\r\n$4\r\nping\r\n";
    boost::asio::write(socket, boost::asio::buffer(ping_msg));

    // receive the response of ping command
    char flag;
    boost::asio::read(socket, boost::asio::buffer(&flag, sizeof(flag)));
    // '+' stands for success
    // '-' stands for failure
    // std::cerr << "DEBUGPRINT[1]: redis.cpp:36: flag=" << flag << std::endl;
    if (flag == '+') {
      std::cout << "no password" << std::endl;
      return true;
    }
    // read all the remaining data
    boost::asio::streambuf trash;
    boost::asio::read_until(socket, trash, "\r\n");

    // send password message
    std::string password_msg = "*2\r\n$4\r\nauth\r\n";
    password_msg.push_back('$');
    password_msg += std::to_string(password.size());
    password_msg += "\r\n";
    password_msg += password;
    password_msg += "\r\n";
    // std::cerr << "DEBUGPRINT[2]: redis.cpp:51: password_msg=" << password_msg << std::endl;
    boost::asio::write(socket, boost::asio::buffer(password_msg));

    // receive the response of the password message
    boost::asio::streambuf response_buf;
    std::istream response_is{&response_buf};
    boost::asio::read_until(socket, response_buf, "\r\n");
    std::string response_msg;
    std::copy(std::istream_iterator<char>{response_is},
              std::istream_iterator<char>{}, std::back_inserter(response_msg));
    // std::cerr << "DEBUGPRINT[3]: redis.cpp:62: response_msg=" << response_msg << std::endl;
    if (response_msg.front() == '+') {
      std::cout << "login successfully" << std::endl;
      // DEBUG
      std::this_thread::sleep_for(std::chrono::seconds(10));
      return true;
    } else {
      std::cout << "error: ";
      std::copy(response_msg.begin() + 1, response_msg.end(),
                std::ostream_iterator<char>(std::cout, ""));
      std::cout << std::endl;
      return false;
    }
  }
};

static bool registered =
    ClientFactory::register_client("redis", []() -> std::unique_ptr<Client> {
      return std::make_unique<RedisClient>();
    });
