#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace aika::config {

struct DatabaseConfig final {
    std::string host;
    std::uint16_t port{};
    std::string database;
    std::string username;
    std::string password;
    std::string gm_host;
    std::string gm_username;
    std::string gm_password;
};

struct GameRules final {
    std::uint16_t level_cap{90};
    std::uint16_t max_pran_level{50};
    std::uint16_t delete_days_increment{1};
    std::uint16_t backup_account_delete_days{14};
    std::uint16_t mob_evasion{5};
    std::uint16_t mob_critical_resistance{30};
    std::uint16_t mob_double_resistance{40};
    std::uint16_t guard_physical_attack{600};
    std::uint16_t guard_magical_attack{600};
    std::uint16_t guard_physical_defense{2000};
    std::uint16_t guard_magical_defense{2000};
    std::uint16_t devir_guard_attack{800};
    std::uint16_t devir_guard_defense{3000};
    std::uint16_t devir_stone_attack{900};
    std::uint16_t devir_stone_defense{6000};
    std::uint16_t devir_stone_hp{60000};
    std::uint16_t guard_hp{30000};
    std::uint16_t experience_multiplier{1};
    std::uint16_t honor_per_kill{120};
    std::uint16_t pvp_item_drop_tax{100};
    std::uint16_t skull_multiplier{1};
    std::uint16_t duel_wait_seconds{15};
    std::uint16_t reliquary_establish_minutes{2};
    std::uint16_t reliquary_honor_per_level{250};
    std::uint16_t effect5_rate{10};
    std::uint16_t watch_distance{50};
    std::uint16_t forget_distance{60};
};

struct ServerConfig final {
    std::uint16_t version{};
    std::uint16_t max_users{};
    std::uint16_t channels{1};
    DatabaseConfig mysql;
    std::string asaas_pingback_url;
    std::string asaas_pingback_token;
    GameRules rules;
};

// Reads the core AikaServer.ini settings. Required fields are validated and
// errors never include configuration values, which may contain secrets.
[[nodiscard]] ServerConfig load_server_config(const std::filesystem::path& file);

} // namespace aika::config
