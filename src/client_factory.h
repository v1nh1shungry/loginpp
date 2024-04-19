#pragma once

#ifndef CLIENT_FACTORY_H
#define CLIENT_FACTORY_H

#include "client.h"
#include "noncopyable.hpp"

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

using ClientCreator = std::function<std::unique_ptr<Client>()>;

class ClientFactory final : private Noncopyable {
private:
  static ClientFactory &instance();

public:
  static bool register_client(const std::string &protocol,
                              ClientCreator creator);

  static std::unique_ptr<Client> create(const std::string &protocol);

  static std::vector<std::string> protocols();

  static bool registerd(const std::string &protocol);

private:
  ClientFactory() = default;

private:
  std::unordered_map<std::string, ClientCreator> creators_;
};

#endif // !CLIENT_FACTORY_H
