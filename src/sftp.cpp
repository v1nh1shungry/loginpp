#include "client_factory.h"

#include <boost/asio.hpp>

#include <libssh2.h>
#include <libssh2_sftp.h>

#include <iostream>

class SftpClient final : public Client {
public:
  SftpClient() : Client{22} {}

protected:
  bool login_impl(const std::string &ip, const std::string &username,
                  const std::string &password) override {
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::socket socket{io_context};
    boost::asio::ip::tcp::resolver resolver{io_context};
    boost::asio::connect(socket, resolver.resolve(ip, std::to_string(port_)));

    // create a libssh2 session
    LIBSSH2_SESSION *session;
    int rc;
    // initialize libssh2 library
    rc = libssh2_init(0);
    if (rc != 0) {
      std::cerr << "failed to initialize libssh2" << std::endl;
      return false;
    }

    // create a libssh2 instance
    session = libssh2_session_init();
    if (session == nullptr) {
      std::cerr << "failed to create a libssh2 session" << std::endl;
      libssh2_exit();
      return false;
    }

    // create a libssh2 connection
    rc = libssh2_session_handshake(session, socket.native_handle());
    if (rc != 0) {
      std::cerr << "failed to create a libssh2 connection" << std::endl;
      libssh2_session_free(session);
      libssh2_exit();
      return false;
    }

    // password auth
    rc = libssh2_userauth_password(session, username.c_str(), password.c_str());
    if (rc != 0) {
      std::cerr << "unknown username or invalid password" << std::endl;
      libssh2_session_free(session);
      libssh2_exit();
      return false;
    }

    // create an sftp session
    LIBSSH2_SFTP *sftp_session = libssh2_sftp_init(session);
    if (sftp_session == nullptr) {
      std::cerr << "failed to create an sftp session" << std::endl;
      libssh2_session_disconnect(session, "failure");
      libssh2_session_free(session);
      libssh2_exit();
      return false;
    }

    // clean the connection
    libssh2_sftp_shutdown(sftp_session);
    libssh2_session_disconnect(session, "normal shutdown");
    libssh2_session_free(session);
    libssh2_exit();

    return true;
  }
};

static bool registered =
    ClientFactory::register_client("sftp", []() -> std::unique_ptr<Client> {
      return std::make_unique<SftpClient>();
    });
