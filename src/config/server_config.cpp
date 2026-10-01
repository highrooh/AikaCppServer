#include "aika/config/server_config.hpp"

#include <charconv>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace aika::config {
namespace {

using Section = std::map<std::string, std::string, std::less<>>;
using Ini = std::map<std::string, Section, std::less<>>;

[[nodiscard]] std::string trim(const std::string_view value) {
    constexpr std::string_view whitespace{" \t\r\n"};
    const auto first = value.find_first_not_of(whitespace);
    if (first == std::string_view::npos) {
        return {};
    }
    const auto last = value.find_last_not_of(whitespace);
    return std::string{value.substr(first, last - first + 1U)};
}

[[nodiscard]] std::string normalize(std::string value) {
    for (auto& ch : value) {
        if (ch >= 'A' && ch <= 'Z') {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    return value;
}

[[nodiscard]] Ini parse_ini(const std::filesystem::path& file) {
    std::ifstream input{file, std::ios::binary};
    if (!input) {
        throw std::runtime_error{"Unable to open server configuration: " + file.string()};
    }

    Ini ini;
    std::string current_section;
    std::string line;
    std::size_t line_number = 0U;
    while (std::getline(input, line)) {
        ++line_number;
        if (line_number == 1U && line.size() >= 3U &&
            static_cast<unsigned char>(line[0]) == 0xEFU &&
            static_cast<unsigned char>(line[1]) == 0xBBU &&
            static_cast<unsigned char>(line[2]) == 0xBFU) {
            line.erase(0U, 3U);
        }

        const auto content = trim(line);
        if (content.empty() || content.front() == ';' || content.front() == '#') {
            continue;
        }
        if (content.front() == '[') {
            const auto close = content.find(']');
            if (close == std::string::npos || !trim(std::string_view{content}.substr(close + 1U)).empty()) {
                throw std::runtime_error{"Malformed section in server configuration at line " +
                                         std::to_string(line_number)};
            }
            current_section = normalize(trim(std::string_view{content}.substr(1U, close - 1U)));
            if (current_section.empty()) {
                throw std::runtime_error{"Empty section in server configuration at line " +
                                         std::to_string(line_number)};
            }
            ini.try_emplace(current_section);
            continue;
        }

        const auto equals = content.find('=');
        if (equals == std::string::npos || current_section.empty()) {
            throw std::runtime_error{"Malformed key/value in server configuration at line " +
                                     std::to_string(line_number)};
        }
        const auto key = normalize(trim(std::string_view{content}.substr(0U, equals)));
        if (key.empty()) {
            throw std::runtime_error{"Empty key in server configuration at line " +
                                     std::to_string(line_number)};
        }
        ini[current_section][key] = trim(std::string_view{content}.substr(equals + 1U));
    }

    if (input.bad()) {
        throw std::runtime_error{"Error while reading server configuration: " + file.string()};
    }
    return ini;
}

[[nodiscard]] const std::string* find_value(
    const Ini& ini,
    const std::string_view section,
    const std::string_view key) noexcept {
    const auto section_it = ini.find(section);
    if (section_it == ini.end()) {
        return nullptr;
    }
    const auto key_it = section_it->second.find(key);
    return key_it == section_it->second.end() ? nullptr : &key_it->second;
}

[[nodiscard]] std::string string_value(
    const Ini& ini,
    const std::string_view section,
    const std::string_view key,
    std::string fallback = {}) {
    const auto* value = find_value(ini, section, key);
    return value == nullptr ? std::move(fallback) : *value;
}

[[nodiscard]] std::uint16_t number_value(
    const Ini& ini,
    const std::string_view section,
    const std::string_view key,
    const std::uint16_t fallback,
    const bool required = false) {
    const auto* value = find_value(ini, section, key);
    if (value == nullptr) {
        if (required) {
            throw std::runtime_error{"Missing required server configuration key [" +
                                     std::string{section} + "] " + std::string{key}};
        }
        return fallback;
    }

    unsigned parsed{};
    const auto* begin = value->data();
    const auto* end = begin + value->size();
    const auto result = std::from_chars(begin, end, parsed, 10);
    if (result.ec != std::errc{} || result.ptr != end || parsed > 65535U) {
        throw std::runtime_error{"Invalid numeric server configuration key [" +
                                 std::string{section} + "] " + std::string{key}};
    }
    return static_cast<std::uint16_t>(parsed);
}

void require_nonempty(const std::string& value, const std::string_view section,
                      const std::string_view key) {
    if (value.empty()) {
        throw std::runtime_error{"Missing required server configuration key [" +
                                 std::string{section} + "] " + std::string{key}};
    }
}

} // namespace

ServerConfig load_server_config(const std::filesystem::path& file) {
    const auto ini = parse_ini(file);
    ServerConfig config;

    config.version = number_value(ini, "server", "version", 0U, true);
    config.max_users = number_value(ini, "server", "max_users", 0U, true);
    config.channels = number_value(ini, "server", "channels", 1U);
    if (config.max_users == 0U) {
        throw std::runtime_error{"[Server] MAX_USERS must be greater than zero"};
    }
    if (config.channels == 0U || config.channels > 255U) {
        throw std::runtime_error{"[Server] Channels must be between 1 and 255"};
    }

    auto& mysql = config.mysql;
    mysql.host = string_value(ini, "mysql", "server");
    mysql.port = number_value(ini, "mysql", "port", 0U, true);
    mysql.database = string_value(ini, "mysql", "database");
    mysql.username = string_value(ini, "mysql", "username");
    mysql.password = string_value(ini, "mysql", "password");
    mysql.gm_host = string_value(ini, "mysql", "servergm");
    mysql.gm_username = string_value(ini, "mysql", "usernamegm", mysql.username);
    mysql.gm_password = string_value(ini, "mysql", "passwordgm", mysql.password);
    require_nonempty(mysql.host, "MySQL", "Server");
    require_nonempty(mysql.database, "MySQL", "Database");
    require_nonempty(mysql.username, "MySQL", "Username");
    if (mysql.port == 0U) {
        throw std::runtime_error{"[MySQL] Port must be between 1 and 65535"};
    }

    config.asaas_pingback_url = string_value(ini, "asaas_token", "link");
    config.asaas_pingback_token = string_value(ini, "asaas_token", "token");

    auto& rules = config.rules;
#define AIKA_READ_RULE(member, key) \
    rules.member = number_value(ini, "gameserverconf", key, rules.member)
    AIKA_READ_RULE(level_cap, "level_cap");
    AIKA_READ_RULE(max_pran_level, "max_pran_level");
    AIKA_READ_RULE(delete_days_increment, "delete_days_inc");
    AIKA_READ_RULE(backup_account_delete_days, "days_backup_account_delete");
    AIKA_READ_RULE(mob_evasion, "mob_esquiva");
    AIKA_READ_RULE(mob_critical_resistance, "mob_crit_res");
    AIKA_READ_RULE(mob_double_resistance, "mob_duplo_res");
    AIKA_READ_RULE(guard_physical_attack, "mob_guard_patk");
    AIKA_READ_RULE(guard_magical_attack, "mob_guard_matk");
    AIKA_READ_RULE(guard_physical_defense, "mob_guard_pdef");
    AIKA_READ_RULE(guard_magical_defense, "mob_guard_mdef");
    AIKA_READ_RULE(devir_guard_attack, "mob_guard_devir_atk");
    AIKA_READ_RULE(devir_guard_defense, "mob_guard_devir_def");
    AIKA_READ_RULE(devir_stone_attack, "mob_stone_devir_atk");
    AIKA_READ_RULE(devir_stone_defense, "mob_stone_devir_def");
    AIKA_READ_RULE(devir_stone_hp, "mob_stone_hp");
    AIKA_READ_RULE(guard_hp, "mob_guard_hp");
    AIKA_READ_RULE(experience_multiplier, "exp_multiplier");
    AIKA_READ_RULE(honor_per_kill, "honor_per_kill");
    AIKA_READ_RULE(pvp_item_drop_tax, "pvp_item_drop_tax");
    AIKA_READ_RULE(skull_multiplier, "skull_multiplier");
    AIKA_READ_RULE(duel_wait_seconds, "duel_time_wait");
    AIKA_READ_RULE(reliquary_establish_minutes, "reliq_est_time");
    AIKA_READ_RULE(reliquary_honor_per_level, "inc_honor_reliq_level");
    AIKA_READ_RULE(effect5_rate, "rate_effect5");
    AIKA_READ_RULE(watch_distance, "distance_to_watch");
    AIKA_READ_RULE(forget_distance, "distance_to_forget");
#undef AIKA_READ_RULE

    return config;
}

} // namespace aika::config
