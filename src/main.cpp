#include "client_factory.h"

#include <argparse/argparse.hpp>

#include <iostream>

int main(int argc, char *argv[]) {
  argparse::ArgumentParser program{"cli"};
  program.add_argument("--protocol").help("Protocol used").required();
  program.add_argument("--host").help("Hostname").required();
  program.add_argument("--username").help("Username to login").required();
  program.add_argument("--password").help("Password to login").required();

  try {
    program.parse_args(argc, argv);
  } catch (const std::exception &err) {
    std::cerr << err.what() << std::endl;
    std::cerr << program;
    std::exit(1);
  }

  const std::string protocol = program.get("--protocol");
  const std::string host = program.get("--host");
  const std::string username = program.get("--username");
  const std::string password = program.get("--password");

  if (ClientFactory::registerd(protocol)) {
    auto client = ClientFactory::create(protocol);
    client->login(host, username, password);
  } else {
    std::cerr << "Unknown protocol: " << protocol << std::endl;
    return 1;
  }

  return 0;
}
