#include "client_factory.h"

ClientFactory &ClientFactory::instance() {
  static ClientFactory inst;
  return inst;
}

bool ClientFactory::register_client(const std::string &protocol,
                                    ClientCreator creator) {
  instance().creators_[protocol] = std::move(creator);
  return true;
}

std::unique_ptr<Client> ClientFactory::create(const std::string &protocol) {
  return instance().creators_[protocol]();
}

std::vector<std::string> ClientFactory::protocols() {
  std::vector<std::string> res;
  for (const auto &[k, _] : instance().creators_)
    res.push_back(k);
  return res;
}

bool ClientFactory::registerd(const std::string &protocol) {
  return instance().creators_.count(protocol);
}
