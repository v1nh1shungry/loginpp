#include "client_factory.h"

#include <boost/asio.hpp>
#include <boost/uuid/detail/sha1.hpp>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

// Hash password using insecure pre 4.1 method
static std::string scramble_old_password(const std::string &scramble,
                                         const std::string &password) {
  // Generate binary hash from byte string using insecure pre 4.1 method
  auto pw_hash = [](std::string_view password) {
    uint32_t add = 7;
    uint32_t tmp;
    std::array<uint32_t, 2> result;
    result[0] = 1345345333;
    result[1] = 0x12345671;
    for (char c : password) {
      if (c == ' ' or c == '\t') {
        continue;
      }
      tmp = static_cast<uint32_t>(c);
      result[0] ^= (((result[0] & 63) + add) * tmp) + (result[0] << 8);
      result[1] += (result[1] << 8) ^ result[0];
      add += tmp;
    }
    // Remove sign bit (1<<31)-1)
    result[0] &= 0x7FFFFFFF;
    result[1] &= 0x7FFFFFFF;
    return result;
  };

  auto hash_pw = pw_hash(password);
  auto hash_sc = pw_hash({scramble.c_str(), 8});

  constexpr uint32_t rnd_max_val = 0x3FFFFFFF;
  auto next_byte = [](std::pair<uint32_t, uint32_t> r) {
    r.first = (r.first * 3 + r.second) % rnd_max_val;
    r.second = (r.first + r.second + 33) % rnd_max_val;
    return static_cast<uint8_t>(static_cast<uint64_t>(r.first) * 31 /
                                rnd_max_val);
  };
  std::pair<uint32_t, uint32_t> rnd{hash_pw[0] ^ hash_sc[0] % rnd_max_val,
                                    hash_pw[1] ^ hash_sc[1] % rnd_max_val};
  std::string out;
  out.resize(8);
  for (int i = 0; i < 8; ++i) {
    out[i] = next_byte(rnd) + 64;
  }
  auto mask = next_byte(rnd);
  for (int i = 0; i < 8; ++i) {
    out[i] ^= mask;
  }
  return out;
}

// Hash password using 4.1+ method (SHA1)
static std::string scramble_password(const std::string &scramble,
                                     const std::string &password) {
  boost::uuids::detail::sha1 sha1;
  // stage1Hash = SHA1(password)
  sha1.process_bytes(password.c_str(), password.size());
  boost::uuids::detail::sha1::digest_type stage1;
  sha1.get_digest(stage1);
  // scrambleHash = SHA1(scramble + SHA1(stage1Hash))
  sha1.reset();
  sha1.process_bytes(stage1, sizeof(stage1));
  boost::uuids::detail::sha1::digest_type hash;
  sha1.get_digest(hash);
  sha1.reset();
  sha1.process_bytes(scramble.c_str(), scramble.size());
  sha1.process_bytes(hash, sizeof(hash));
  decltype(hash) scramble_hash;
  sha1.get_digest(scramble_hash);
  char *scramble_ptr = reinterpret_cast<char *>(scramble_hash);
  char *stage1_ptr = reinterpret_cast<char *>(stage1);
  // token = scrambleHash XOR stage1Hash
  for (size_t i = 0; i < sizeof(scramble_hash); ++i) {
    scramble_ptr[i] ^= stage1_ptr[i];
  }
  return {reinterpret_cast<char *>(scramble_hash), sizeof(scramble_hash)};
}

// Hash password using MySQL 8+ method (SHA256)
static std::string scramble_sha256_password(const std::string &scramble,
                                            const std::string &password) {
  // XOR(SHA256(password), SHA256(SHA256(SHA256(password)), scramble))
  unsigned char msg1[SHA256_DIGEST_LENGTH];
  {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password.c_str(), password.size());
    SHA256_Final(msg1, &sha256);
  }
  unsigned char msg1_hash[SHA256_DIGEST_LENGTH];
  {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, msg1, sizeof(msg1));
    SHA256_Final(msg1_hash, &sha256);
  }
  unsigned char msg2[SHA256_DIGEST_LENGTH];
  {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, msg1_hash, sizeof(msg1_hash));
    SHA256_Update(&sha256, scramble.c_str(), scramble.size());
    SHA256_Final(msg2, &sha256);
  }
  for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    msg1[i] ^= msg2[i];
  }
  return {reinterpret_cast<char *>(msg1), sizeof(msg1)};
}

class MysqlClient final : public Client {
public:
  MysqlClient() : Client{3306} {}

protected:
  bool login_impl(const std::string &ip, const std::string &username,
                  const std::string &password) override {
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::socket socket{io_context};
    boost::asio::ip::tcp::resolver resolver{io_context};
    boost::asio::connect(socket, resolver.resolve(ip, std::to_string(port_)));

    // read the server's handshake packet
    // read packet header (packet length)
    int32_t packet_length = 0;
    boost::asio::read(
        socket, boost::asio::buffer(&packet_length, sizeof(packet_length)));
    reinterpret_cast<char *>(&packet_length)[3] = 0;
    std::cerr << "DEBUGPRINT[2]: mysql.cpp:57: packet_length=" << packet_length
              << std::endl;
    std::vector<char> handshake_buf;
    std::size_t pos = 0;
    handshake_buf.resize(packet_length);
    boost::asio::read(socket, boost::asio::buffer(handshake_buf));
    // read protocol version
    int8_t protocol_version = handshake_buf[pos];
    pos += 1;
    // read server version
    std::string server_version;
    for (; pos < handshake_buf.size() and handshake_buf[pos]; ++pos) {
      server_version.push_back(handshake_buf[pos]);
    }
    std::cerr << "DEBUGPRINT[3]: mysql.cpp:65: server_version="
              << server_version << std::endl;
    pos += 1;
    // read thread id
    pos += 4;
    // read first part of password cipher
    std::string auth_data1;
    auth_data1.resize(8);
    for (int i = 0; i < 8; ++i) {
      auth_data1[i] = handshake_buf[pos + i];
    }
    pos += 8;
    // read filter
    pos += 1;
    // read capability flag
    pos += 2;
    // read character set
    uint8_t character_set = handshake_buf[pos];
    pos += 1;
    // read server status
    pos += 2;
    // read capability flag
    pos += 2;
    // read length of auth plugin data
    int8_t auth_plugin_data_len = handshake_buf[pos];
    pos += 1;
    // read reserved
    pos += 10;
    // read second part of password cypher
    std::string auth_data2;
    auth_data2.resize(12);
    for (int i = 0; i < 12; ++i) {
      auth_data2[i] = handshake_buf[pos + i];
    }
    pos += 13;
    // read the auth plugin name
    std::string auth_plugin_name;
    for (; pos < handshake_buf.size(); ++pos) {
      auth_plugin_name.push_back(handshake_buf[pos]);
    }
    std::cerr << "DEBUGPRINT[4]: mysql.cpp:108: auth_plugin_name="
              << auth_plugin_name << std::endl;
    if (auth_plugin_name.empty()) {
      auth_plugin_name = "mysql_native_password";
    }

    // construct the password cypher
    std::string auth_data = auth_data1 + auth_data2;
    std::string auth_result = scramble_sha256_password(auth_data, password);

    // construct the response packet
    std::vector<unsigned char> response_buf;
    // client capability flag
    // 512 -> clientProtocol41
    // 524288 -> clientPluginAuth
    int32_t capability_flag = 512 | 524288;
    std::copy(reinterpret_cast<char *>(&capability_flag),
              reinterpret_cast<char *>(&capability_flag) +
                  sizeof(capability_flag),
              std::back_inserter(response_buf));
    // max size
    for (int i = 0; i < 4; ++i) {
      response_buf.push_back(0);
    }
    // character set, utf-8
    response_buf.push_back(255);
    // reserved
    for (int i = 0; i < 23; ++i) {
      response_buf.push_back(0);
    }
    // username
    std::copy(username.begin(), username.end(),
              std::back_inserter(response_buf));
    response_buf.push_back(0);
    // auth
    uint8_t auth_len = static_cast<uint8_t>(auth_result.size());
    response_buf.push_back(auth_len);
    std::copy(auth_result.begin(), auth_result.end(),
              std::back_inserter(response_buf));
    // plugin
    std::copy(auth_plugin_name.begin(), auth_plugin_name.end(),
              std::back_inserter(response_buf));
    response_buf.push_back(0);

    uint32_t response_length = response_buf.size();
    // sequence
    reinterpret_cast<char *>(&response_length)[3] = 1;
    boost::asio::write(
        socket, boost::asio::buffer(&response_length, sizeof(response_length)));
    boost::asio::write(socket, boost::asio::buffer(response_buf));

    // read auth result
    int32_t result_length = 0;
    boost::asio::read(
        socket, boost::asio::buffer(&result_length, sizeof(result_length)));
    reinterpret_cast<char *>(&result_length)[3] = 0;
    std::cerr << "DEBUGPRINT[5]: mysql.cpp:165: result_length=" << result_length
              << std::endl;
    int8_t header;
    boost::asio::read(socket, boost::asio::buffer(&header, sizeof(header)));
    if (header == 0 or header == 1) {
      std::cout << "login successfully" << std::endl;
      // DEBUG
      std::this_thread::sleep_for(std::chrono::seconds(5));
      return true;
      // } else if (header == 1) {
      //   int8_t flag;
      //   boost::asio::read(socket, boost::asio::buffer(&flag, sizeof(flag)));
      //   std::cerr << "DEBUGPRINT[1]: mysql.cpp:208: flag="
      //             << static_cast<int>(flag) << std::endl;
      //   return true;
    }
    std::cerr << "error code: " << std::hex << static_cast<unsigned int>(header)
              << std::endl;
    std::string result_buf;
    result_buf.resize(result_length - 1);
    boost::asio::read(socket, boost::asio::buffer(result_buf));
    std::cerr << "DEBUGPRINT[6]: mysql.cpp:179: result_buf=" << result_buf
              << std::endl;
    return false;
  }
};

static bool registerd =
    ClientFactory::register_client("mysql", []() -> std::unique_ptr<Client> {
      return std::make_unique<MysqlClient>();
    });
