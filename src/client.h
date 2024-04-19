#pragma once
#ifndef CLIENT_H
#define CLIENT_H

#include <string>

class Client {
protected:
  int port_;

protected:
  virtual bool login_impl(const std::string &ip, const std::string &username,
                          const std::string &password) = 0;

private:
  bool is_port_open(const std::string &ip);

public:
  explicit Client(int port);

  virtual ~Client() = default;

  void login(const std::string &ip, const std::string &username,
             const std::string &password);
};

#endif // !CLIENT_H
