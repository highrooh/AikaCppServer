#pragma once

#include "aika/auth/account_auth.hpp"
#include "aika/config/server_config.hpp"
#include "aika/data/game_tables.hpp"
#include "aika/data/server_list.hpp"
#include "aika/data/world_data.hpp"
#include "aika/network/tcp_listener.hpp"

#include <memory>
#include <vector>

namespace aika::server {

class GameChannels final {
public:
    GameChannels(config::ServerConfig config,
                 std::vector<data::ServerEntry> servers,
                 const data::GameTables& tables,
                 const data::WorldData& world_data,
                 std::shared_ptr<auth::LoginGrantRegistry> login_grants);
    ~GameChannels();
    GameChannels(const GameChannels&) = delete;
    GameChannels& operator=(const GameChannels&) = delete;

    void start();
    void stop() noexcept;

private:
    config::ServerConfig config_;
    std::vector<data::ServerEntry> servers_;
    const data::GameTables* tables_{};
    const data::WorldData* world_data_{};
    std::shared_ptr<auth::LoginGrantRegistry> login_grants_;
    std::vector<std::unique_ptr<network::TcpListener>> listeners_;
};

} // namespace aika::server
