#pragma once

#include "aika/auth/account_auth.hpp"
#include "aika/config/server_config.hpp"
#include "aika/data/server_list.hpp"
#include "aika/network/tcp_listener.hpp"

#include <string>
#include <memory>
#include <vector>

namespace aika::server {

class AuthListeners final {
public:
    AuthListeners(config::ServerConfig config, std::vector<data::ServerEntry> servers,
                  std::shared_ptr<auth::LoginGrantRegistry> login_grants);
    ~AuthListeners();
    AuthListeners(const AuthListeners&) = delete;
    AuthListeners& operator=(const AuthListeners&) = delete;

    void start();
    void stop() noexcept;

private:
    config::ServerConfig config_;
    std::vector<data::ServerEntry> servers_;
    std::shared_ptr<auth::LoginGrantRegistry> login_grants_;
    std::string server_players_response_;
    network::TcpListener login_listener_;
    network::TcpListener token_listener_;
};

} // namespace aika::server
