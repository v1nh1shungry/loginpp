#include "client.h"

#include <boost/asio.hpp>

#include <iostream>

bool Client::is_port_open(const std::string &ip) {
  try {
    using namespace boost::asio;
    io_context io_context;
    ip::tcp::socket socket{io_context};
    ip::tcp::resolver resolver{io_context};
    boost::asio::connect(socket, resolver.resolve(ip, std::to_string(port_)));
    return true;
  } catch (const std::exception &err) {
    std::cerr << err.what() << std::endl;
    return false;
  }
}

Client::Client(int port) : port_{port} {}

void Client::login(const std::string &ip, const std::string &username,
                   const std::string &password) {
  if (is_port_open(ip)) {
    login_impl(ip, username, password);
  } else {
    std::cerr << "Port " << port_ << " on " << ip << " is closed" << std::endl;
  }
}
