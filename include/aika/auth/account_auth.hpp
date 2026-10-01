#pragma once

#include "aika/config/server_config.hpp"

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace aika::auth {

class AccountAuthService final {
public:
    explicit AccountAuthService(config::DatabaseConfig database_config);

    // Returns the legacy token endpoint result body. Account passwords and
    // tokens are handled in memory and are never written to logs.
    [[nodiscard]] std::string issue_token(
        const std::string& username, const std::string& password,
        bool allow_loopback_plaintext = false) const;
    [[nodiscard]] std::string character_count(
        const std::string& username, const std::string& token) const;
    [[nodiscard]] std::string renew_token(
        const std::string& username, const std::string& token) const;

private:
    config::DatabaseConfig database_config_;
};

// One-time handoff from the authenticated login listener to a game channel.
// The grant is short-lived, bound to the peer address, and consumed once.
class LoginGrantRegistry final {
public:
    void authorize(std::string username, std::uint32_t account_id,
                   std::string peer_address);
    [[nodiscard]] bool consume(const std::string& username,
                               std::uint32_t account_id,
                               const std::string& peer_address);

private:
    struct Grant final {
        std::uint32_t account_id{};
        std::string peer_address;
        std::chrono::steady_clock::time_point expires_at{};
    };

    std::mutex mutex_;
    std::unordered_map<std::string, Grant> grants_;
};

} // namespace aika::auth
