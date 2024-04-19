#include "client_factory.h"

#include <boost/asio.hpp>

#include <iostream>
#include <string>

using namespace std;
using namespace boost::asio::ip;

static bool send_command(tcp::socket &socket, string str_command,
                        string &str_result) {
  boost::asio::streambuf request;
  boost::asio::streambuf response;
  std::string str_line;
  std::ostream request_stream(&request);
  std::istream response_stream(&response);

  if (str_command != "") {
    str_command += ("\r\n");
    cout << str_command;
    request_stream << str_command;
    boost::asio::write(socket, request);
  }
  // if (strCommand != "") {
  //   strCommand += ("\r\n");
  //   cout << strCommand;
  //   request_stream << strCommand;
  //   boost::asio::write(socket, request);
  // }
  boost::asio::read_until(socket, response, "\r\n");
  std::getline(response_stream, str_result);
  cout << str_result << endl;
  return true;
}

class FtpClient final : public Client {
public:
  FtpClient() : Client{21} {}

private:
  bool login_impl(const std::string &ip, const std::string &username,
                  const std::string &password) override {
    boost::asio::io_context io_context;
    tcp::socket socket(io_context);
    tcp::resolver resolver(io_context);
    boost::asio::connect(socket, resolver.resolve(ip, std::to_string(port_)));

    string str_result;

    send_command(socket, "", str_result);
    /// send USER
    send_command(socket, "USER " + username, str_result);
    /// send PASSWORD
    send_command(socket, "PASS " + password, str_result);

    if (str_result.substr(0, 3) == "230")
      return true;
    return false;
  }
};

static bool registered =
    ClientFactory::register_client("ftp", []() -> std::unique_ptr<Client> {
      return std::make_unique<FtpClient>();
    });
