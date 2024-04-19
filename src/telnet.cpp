#include "client.h"
#include "client_factory.h"

#include <boost/asio.hpp>

#include <iostream>

// the "Interpret as Command" (IAC) escape character followed by the code for
// the command.
constexpr static char IAC = 255;
// Indicates the request that the other party perform, or confirmation that you
// are expecting the other party to perform, the indicated option.
constexpr static char DO = 253;
// Indicates the desire to begin performing, or confirmation that you are now
// performing, the indicated option.
constexpr static char WILL = 251;
// Indicates the refusal to perform, or continue performing, the indicated
// option.
constexpr static char WONT = 252;
// Indicates the demand that the other party stop performing, or confirmation
// that you are no longer expecting the other party to perform, the indicated
// option.
constexpr static char DONT = 254;

using namespace boost::asio::ip;

static std::pair<bool, std::string> parse(const std::string &data) {
  std::size_t index = 0;
  std::string result;
  while (index < data.size() and data[index] == IAC) {
    char cmd = data[index + 1];
    char info = data[index + 2];
    bool defined = info == 1 or info == 3;
    std::string echo;
    echo.push_back(static_cast<char>(IAC));
    switch (cmd) {
    case DO:
      echo.push_back(static_cast<char>(defined ? WILL : WONT));
      break;
    case WILL:
      echo.push_back(static_cast<char>(defined ? DO : DONT));
      break;
    case DONT:
      echo.push_back(static_cast<char>(WONT));
      break;
    case WONT:
      echo.push_back(static_cast<char>(DONT));
      break;
    }
    echo.push_back(info);
    result += echo;
    index += 3;
  }
  if (result.empty())
    return {false, data};
  return {true, result};
}

static void send_echo(tcp::socket &socket, const std::string &echo);

static void receive(tcp::socket &socket) {
  constexpr int BUFFER_SIZE = 1024;
  char content[BUFFER_SIZE];
  socket.read_some(boost::asio::buffer(content));
  auto [parsed, result] = parse(content);
  if (parsed)
    send_echo(socket, result);
  else
    std::cout << result << std::endl;
}

static void send_echo(tcp::socket &socket, const std::string &echo) {
  socket.send(boost::asio::buffer(echo));
  receive(socket);
}

class TelnetClient final : public Client {
public:
  TelnetClient() : Client{23} {}

protected:
  bool login_impl(const std::string &ip, const std::string &username,
                  const std::string &password) override {
    boost::asio::io_context io_context;
    tcp::socket socket{io_context};
    tcp::resolver resolver{io_context};
    boost::asio::connect(socket, resolver.resolve(ip, std::to_string(port_)));

    receive(socket);
    receive(socket);

    const std::string LFCR = "\r\n";
    for (char c : username) {
      socket.send(boost::asio::buffer(&c, 1));
      boost::asio::read(socket, boost::asio::buffer(&c, 1));
    }
    socket.send(boost::asio::buffer(LFCR));
    receive(socket);
    receive(socket);
    socket.send(boost::asio::buffer(password));
    socket.send(boost::asio::buffer(LFCR));
    receive(socket);
    receive(socket);
    // socket.send(boost::asio::buffer(LFCR));
    // receive(socket);
    // receive(socket);
    // socket.send(boost::asio::buffer(password));
    // socket.send(boost::asio::buffer(LFCR));
    // receive(socket);
    // receive(socket);
    return true;
  }
};

static bool registered =
    ClientFactory::register_client("telnet", []() -> std::unique_ptr<Client> {
      return std::make_unique<TelnetClient>();
    });
