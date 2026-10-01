#include "aika/database/mysql_connection.hpp"

#include <mysql.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace aika::database {
namespace {

[[nodiscard]] std::runtime_error mysql_exception(MYSQL* handle, const char* action) {
    return std::runtime_error{std::string{action} + ": " + ::mysql_error(handle)};
}

[[nodiscard]] std::uint64_t read_mysql_number(const MYSQL_ROW row,
        const unsigned long* lengths, const unsigned index) noexcept {
    if (row == nullptr || lengths == nullptr || row[index] == nullptr || lengths[index] == 0U)
        return 0U;
    return std::strtoull(row[index], nullptr, 10);
}

} // namespace

struct MysqlConnection::Impl final {
    MYSQL* handle{};
    config::DatabaseConfig config;

    ~Impl() {
        if (handle != nullptr) {
            mysql_close(handle);
        }
    }

    void connect() {
        MYSQL* candidate = mysql_init(nullptr);
        if (candidate == nullptr) {
            throw std::runtime_error{"Unable to initialize the MySQL client"};
        }
        unsigned int timeout_seconds = 5U;
        if (mysql_options(candidate, MYSQL_OPT_CONNECT_TIMEOUT, &timeout_seconds) != 0 ||
            mysql_options(candidate, MYSQL_SET_CHARSET_NAME, "utf8mb4") != 0) {
            const std::string message = mysql_error(candidate);
            mysql_close(candidate);
            throw std::runtime_error{"Unable to configure the MySQL client: " + message};
        }
        if (mysql_real_connect(candidate, config.host.c_str(), config.username.c_str(),
                config.password.c_str(), config.database.c_str(), config.port, nullptr, 0) == nullptr) {
            const std::string message = mysql_error(candidate);
            mysql_close(candidate);
            throw std::runtime_error{"Unable to connect to MySQL: " + message};
        }
        if (mysql_set_character_set(candidate, "utf8mb4") != 0) {
            const std::string message = mysql_error(candidate);
            mysql_close(candidate);
            throw std::runtime_error{"Unable to select utf8mb4: " + message};
        }
        handle = candidate;
    }

    void ensure_connected() {
        if (handle != nullptr && mysql_ping(handle) == 0) {
            return;
        }
        if (handle != nullptr) {
            mysql_close(handle);
            handle = nullptr;
        }
        std::string last_error;
        for (unsigned attempt = 0U; attempt < 3U; ++attempt) {
            try {
                connect();
                return;
            } catch (const std::exception& error) {
                last_error = error.what();
                if (attempt < 2U) {
                    std::this_thread::sleep_for(std::chrono::milliseconds{250U << attempt});
                }
            }
        }
        throw std::runtime_error{"MySQL reconnect failed after 3 attempts: " + last_error};
    }
};

MysqlConnection::MysqlConnection(const config::DatabaseConfig& config)
    : impl_{std::make_unique<Impl>()} {
    impl_->config = config;
    impl_->connect();
}

MysqlConnection::~MysqlConnection() = default;
MysqlConnection::MysqlConnection(MysqlConnection&&) noexcept = default;
MysqlConnection& MysqlConnection::operator=(MysqlConnection&&) noexcept = default;

bool MysqlConnection::connected() const noexcept {
    if (impl_ == nullptr) {
        return false;
    }
    try {
        impl_->ensure_connected();
        return true;
    } catch (...) {
        return false;
    }
}

std::vector<ColumnMetadata> MysqlConnection::inspect_schema() const {
    impl_->ensure_connected();
    constexpr char query[] =
        "SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY "
        "FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() "
        "ORDER BY TABLE_NAME, ORDINAL_POSITION";
    if (mysql_real_query(impl_->handle, query, sizeof(query) - 1U) != 0) {
        throw mysql_exception(impl_->handle, "Unable to inspect the MySQL schema");
    }

    MYSQL_RES* result = mysql_store_result(impl_->handle);
    if (result == nullptr) {
        throw mysql_exception(impl_->handle, "Unable to read MySQL schema metadata");
    }
    std::vector<ColumnMetadata> columns;
    const auto count = mysql_num_rows(result);
    columns.reserve(static_cast<std::size_t>(count));
    MYSQL_ROW row{};
    while ((row = mysql_fetch_row(result)) != nullptr) {
        columns.push_back(ColumnMetadata{
            .table = row[0] == nullptr ? "" : row[0],
            .name = row[1] == nullptr ? "" : row[1],
            .type = row[2] == nullptr ? "" : row[2],
            .nullable = row[3] != nullptr && row[3][0] == 'Y',
            .primary_key = row[4] != nullptr && row[4][0] == 'P',
        });
    }
    mysql_free_result(result);
    return columns;
}

std::optional<AccountRecord> MysqlConnection::find_account(
    const std::string& username) const {
    impl_->ensure_connected();
    constexpr char query[] =
        "SELECT id, password_hash, COALESCE(last_token, ''), "
        "COALESCE(last_token_creation_time, 0), COALESCE(nation, 0), "
        "COALESCE(account_status, 0), COALESCE(account_type, 0), "
        "COALESCE(premium_time, 0), COALESCE(storage_gold, 0), COALESCE(ban_days, 0), "
        "COALESCE(cash, 0) "
        "FROM accounts WHERE username = ? LIMIT 1";
    MYSQL_STMT* statement = mysql_stmt_init(impl_->handle);
    if (statement == nullptr) {
        throw mysql_exception(impl_->handle, "Unable to allocate MySQL statement");
    }
    const auto close_statement = [&statement] { mysql_stmt_close(statement); };
    if (mysql_stmt_prepare(statement, query, sizeof(query) - 1U) != 0) {
        const std::string message = mysql_stmt_error(statement);
        close_statement();
        throw std::runtime_error{"Unable to prepare account query: " + message};
    }

    MYSQL_BIND parameter{};
    unsigned long username_length = static_cast<unsigned long>(username.size());
    parameter.buffer_type = MYSQL_TYPE_STRING;
    parameter.buffer = const_cast<char*>(username.data());
    parameter.buffer_length = username_length;
    parameter.length = &username_length;
    if (mysql_stmt_bind_param(statement, &parameter) != 0 ||
        mysql_stmt_execute(statement) != 0) {
        const std::string message = mysql_stmt_error(statement);
        close_statement();
        throw std::runtime_error{"Unable to query account: " + message};
    }

    AccountRecord account{};
    std::array<char, 33> password_hash{};
    std::array<char, 33> token{};
    unsigned long password_length{};
    unsigned long token_length{};
    MYSQL_BIND result[11]{};
    result[0].buffer_type = MYSQL_TYPE_LONG;
    result[0].buffer = &account.id;
    result[0].is_unsigned = true;
    result[1].buffer_type = MYSQL_TYPE_STRING;
    result[1].buffer = password_hash.data();
    result[1].buffer_length = static_cast<unsigned long>(password_hash.size());
    result[1].length = &password_length;
    result[2].buffer_type = MYSQL_TYPE_STRING;
    result[2].buffer = token.data();
    result[2].buffer_length = static_cast<unsigned long>(token.size());
    result[2].length = &token_length;
    result[3].buffer_type = MYSQL_TYPE_LONGLONG;
    result[3].buffer = &account.last_token_creation_time;
    result[4].buffer_type = MYSQL_TYPE_LONG;
    result[4].buffer = &account.nation;
    result[4].is_unsigned = true;
    result[5].buffer_type = MYSQL_TYPE_LONG;
    result[5].buffer = &account.account_status;
    result[5].is_unsigned = true;
    result[6].buffer_type = MYSQL_TYPE_TINY;
    result[6].buffer = &account.account_type;
    result[6].is_unsigned = true;
    result[7].buffer_type = MYSQL_TYPE_LONGLONG;
    result[7].buffer = &account.premium_time;
    result[7].is_unsigned = true;
    result[8].buffer_type = MYSQL_TYPE_LONGLONG;
    result[8].buffer = &account.storage_gold;
    result[8].is_unsigned = true;
    result[9].buffer_type = MYSQL_TYPE_LONG;
    result[9].buffer = &account.ban_days;
    result[9].is_unsigned = true;
    result[10].buffer_type = MYSQL_TYPE_LONG;
    result[10].buffer = &account.cash;
    result[10].is_unsigned = true;
    if (mysql_stmt_bind_result(statement, result) != 0 ||
        mysql_stmt_store_result(statement) != 0) {
        const std::string message = mysql_stmt_error(statement);
        close_statement();
        throw std::runtime_error{"Unable to read account row: " + message};
    }

    const auto fetch_status = mysql_stmt_fetch(statement);
    if (fetch_status == MYSQL_NO_DATA) {
        close_statement();
        return std::nullopt;
    }
    if (fetch_status != 0 && fetch_status != MYSQL_DATA_TRUNCATED) {
        const std::string message = mysql_stmt_error(statement);
        close_statement();
        throw std::runtime_error{"Unable to fetch account row: " + message};
    }
    account.password_hash.assign(password_hash.data(),
        std::min<unsigned long>(password_length, static_cast<unsigned long>(password_hash.size())));
    account.last_token.assign(token.data(),
        std::min<unsigned long>(token_length, static_cast<unsigned long>(token.size())));
    close_statement();

    const auto storage_query = std::string{
        "SELECT slot, item_id, app, identific, effect1_index, effect2_index, "
        "effect3_index, effect1_value, effect2_value, effect3_value, min, max, "
        "refine, time FROM items WHERE owner_id = "} + std::to_string(account.id) +
        " AND slot_type = 2 AND slot < 86 ORDER BY slot LIMIT 86";
    if (mysql_real_query(impl_->handle, storage_query.data(),
            static_cast<unsigned long>(storage_query.size())) != 0)
        throw mysql_exception(impl_->handle, "Unable to query account storage items");
    MYSQL_RES* storage_rows = mysql_store_result(impl_->handle);
    if (storage_rows == nullptr)
        throw mysql_exception(impl_->handle, "Unable to read account storage items");
    MYSQL_ROW storage_row{};
    while ((storage_row = mysql_fetch_row(storage_rows)) != nullptr) {
        auto* lengths = mysql_fetch_lengths(storage_rows);
        if (lengths == nullptr) {
            mysql_free_result(storage_rows);
            throw mysql_exception(impl_->handle, "Unable to read account storage item fields");
        }
        const auto slot = static_cast<std::size_t>(read_mysql_number(storage_row, lengths, 0U));
        if (slot >= account.storage_items.size()) continue;
        auto& item = account.storage_items[slot];
        item.item_id = static_cast<std::uint32_t>(read_mysql_number(storage_row, lengths, 1U));
        item.app = static_cast<std::uint32_t>(read_mysql_number(storage_row, lengths, 2U));
        item.identific = static_cast<std::uint32_t>(read_mysql_number(storage_row, lengths, 3U));
        for (unsigned i = 0U; i < item.effect_index.size(); ++i) {
            item.effect_index[i] = static_cast<std::uint32_t>(read_mysql_number(
                storage_row, lengths, 4U + i));
            item.effect_value[i] = static_cast<std::uint32_t>(read_mysql_number(
                storage_row, lengths, 7U + i));
        }
        item.min = static_cast<std::uint32_t>(read_mysql_number(storage_row, lengths, 10U));
        item.max = static_cast<std::uint32_t>(read_mysql_number(storage_row, lengths, 11U));
        item.refine = static_cast<std::uint32_t>(read_mysql_number(storage_row, lengths, 12U));
        item.time = static_cast<std::uint32_t>(read_mysql_number(storage_row, lengths, 13U));
    }
    mysql_free_result(storage_rows);

    // Delphi initializes the account's principal storage bag at slot 80 when
    // creating a character. Older accounts (and accounts created by this C++
    // server) may not have that row in `items`, so mirror the Delphi default
    // in the loaded account state. Keep a real item already occupying slot 80.
    if (account.storage_items[80U].item_id == 0U)
        account.storage_items[80U].item_id = 5310U;

    return account;
}

std::vector<CharacterRecord> MysqlConnection::load_characters(
        const std::uint32_t account_id, const bool include_details) const {
    impl_->ensure_connected();
    const auto query = std::string{
        "SELECT id, slot, numeric_errors, deleted, numeric_token, name, classinfo, "
        "strength, agility, intelligence, constitution, luck, status, altura, tronco, "
        "perna, corpo, curhp, curmp, honor, killpoint, infamia, skillpoint, experience, "
        "level, guildindex, gold, creationtime, logintime, speedmove, rotation, loggedtime, "
        "playerkill, posx, posy, delete_time, active_title, "
        "COALESCE(NULLIF(last_diary_event, ''), 0), saved_posx, saved_posy "
        "FROM characters WHERE owner_accid = "} + std::to_string(account_id) +
        " ORDER BY slot LIMIT 3";
    if (mysql_real_query(impl_->handle, query.data(),
            static_cast<unsigned long>(query.size())) != 0) {
        throw mysql_exception(impl_->handle, "Unable to query account characters");
    }
    MYSQL_RES* result = mysql_store_result(impl_->handle);
    if (result == nullptr) {
        throw mysql_exception(impl_->handle, "Unable to read account characters");
    }

    const auto field = [](MYSQL_ROW row, const unsigned long* lengths,
            const unsigned index) -> std::string_view {
        if (row[index] == nullptr) return {};
        return {row[index], lengths[index]};
    };
    const auto number = [&field](MYSQL_ROW row, const unsigned long* lengths,
            const unsigned index) -> std::uint64_t {
        const auto value = field(row, lengths, index);
        if (value.empty()) return 0U;
        return static_cast<std::uint64_t>(std::strtoull(value.data(), nullptr, 10));
    };
    const auto buff_timestamp = [&field](MYSQL_ROW row,
            const unsigned long* lengths, const unsigned index) -> std::uint64_t {
        const auto value = field(row, lengths, index);
        if (value.empty()) return 0U;
        const std::string text{value};
        char* end{};
        const auto numeric = std::strtoull(text.c_str(), &end, 10);
        if (end != text.c_str() && *end == '\0') return numeric;
        for (const auto* format : {"%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S",
                                   "%m/%d/%Y %H:%M:%S"}) {
            std::tm parsed{};
            std::istringstream input{text};
            input >> std::get_time(&parsed, format);
            if (input.fail()) continue;
            parsed.tm_isdst = -1;
            const auto timestamp = std::mktime(&parsed);
            if (timestamp >= 0) return static_cast<std::uint64_t>(timestamp);
        }
        return 0U;
    };

    std::vector<CharacterRecord> characters;
    MYSQL_ROW row{};
    while ((row = mysql_fetch_row(result)) != nullptr) {
        auto* lengths = mysql_fetch_lengths(result);
        if (lengths == nullptr) {
            mysql_free_result(result);
            throw mysql_exception(impl_->handle, "Unable to read character fields");
        }
        CharacterRecord character{};
        character.id = static_cast<std::uint32_t>(number(row, lengths, 0U));
        character.slot = static_cast<std::uint32_t>(number(row, lengths, 1U));
        character.numeric_errors = static_cast<std::uint8_t>(number(row, lengths, 2U));
        character.deleted = number(row, lengths, 3U) != 0U;
        character.numeric_token = field(row, lengths, 4U);
        character.name = field(row, lengths, 5U);
        character.class_info = static_cast<std::uint16_t>(number(row, lengths, 6U));
        for (unsigned i = 0U; i < character.attributes.size(); ++i) {
            character.attributes[i] = static_cast<std::uint16_t>(number(row, lengths, 7U + i));
        }
        for (unsigned i = 0U; i < character.sizes.size(); ++i) {
            character.sizes[i] = static_cast<std::uint8_t>(number(row, lengths, 13U + i));
        }
        character.current_hp = static_cast<std::uint32_t>(number(row, lengths, 17U));
        character.current_mp = static_cast<std::uint32_t>(number(row, lengths, 18U));
        character.honor = static_cast<std::uint32_t>(number(row, lengths, 19U));
        character.kill_points = static_cast<std::uint32_t>(number(row, lengths, 20U));
        character.infamy = static_cast<std::uint32_t>(number(row, lengths, 21U));
        character.skill_points = static_cast<std::uint16_t>(number(row, lengths, 22U));
        character.experience = number(row, lengths, 23U);
        character.level = static_cast<std::uint16_t>(number(row, lengths, 24U));
        character.guild_id = static_cast<std::uint32_t>(number(row, lengths, 25U));
        character.gold = number(row, lengths, 26U);
        character.creation_time = static_cast<std::uint32_t>(number(row, lengths, 27U));
        character.login_time = static_cast<std::uint32_t>(number(row, lengths, 28U));
        character.move_speed = static_cast<std::uint32_t>(number(row, lengths, 29U));
        character.rotation = static_cast<std::uint32_t>(number(row, lengths, 30U));
        character.logged_time = static_cast<std::uint32_t>(number(row, lengths, 31U));
        character.player_kill = number(row, lengths, 32U) != 0U;
        const auto x = field(row, lengths, 33U);
        const auto y = field(row, lengths, 34U);
        character.position_x = x.empty() ? 0.0F : std::strtof(x.data(), nullptr);
        character.position_y = y.empty() ? 0.0F : std::strtof(y.data(), nullptr);
        character.delete_time = field(row, lengths, 35U);
        character.active_title = static_cast<std::uint16_t>(number(row, lengths, 36U));
        character.last_diary_event = number(row, lengths, 37U);
        const auto saved_x = field(row, lengths, 38U);
        const auto saved_y = field(row, lengths, 39U);
        character.saved_position_x = saved_x.empty() ? 0.0F : std::strtof(saved_x.data(), nullptr);
        character.saved_position_y = saved_y.empty() ? 0.0F : std::strtof(saved_y.data(), nullptr);
        if (character.slot < 3U) characters.push_back(std::move(character));
    }
    mysql_free_result(result);
    if (!include_details) {
        for (auto& character : characters) {
            const auto equipment_query = std::string{
                "SELECT slot, item_id, app, refine FROM items WHERE owner_id = "} +
                std::to_string(character.id) + " AND slot_type = 0 AND slot < 8 LIMIT 8";
            if (mysql_real_query(impl_->handle, equipment_query.data(),
                    static_cast<unsigned long>(equipment_query.size())) != 0)
                throw mysql_exception(impl_->handle, "Unable to query character equipment");
            result = mysql_store_result(impl_->handle);
            if (result == nullptr)
                throw mysql_exception(impl_->handle, "Unable to read character equipment");
            while ((row = mysql_fetch_row(result)) != nullptr) {
                auto* lengths = mysql_fetch_lengths(result);
                if (lengths == nullptr) {
                    mysql_free_result(result);
                    throw mysql_exception(impl_->handle, "Unable to read equipment fields");
                }
                const auto slot = static_cast<std::size_t>(number(row, lengths, 0U));
                if (slot >= character.equipment.size()) continue;
                character.equipment[slot].item_id = static_cast<std::uint32_t>(number(row, lengths, 1U));
                character.equipment[slot].app = static_cast<std::uint32_t>(number(row, lengths, 2U));
                character.equipment[slot].refine = static_cast<std::uint32_t>(number(row, lengths, 3U));
            }
            mysql_free_result(result);
        }
        return characters;
    }

    const auto load_items = [this, &number](const std::uint32_t character_id,
            const unsigned slot_type, const std::size_t slot_limit,
            auto& destination) {
        const auto query = std::string{
            "SELECT slot, item_id, app, identific, effect1_index, effect2_index, "
            "effect3_index, effect1_value, effect2_value, effect3_value, min, max, "
            "refine, time FROM items WHERE owner_id = "} + std::to_string(character_id) +
            " AND slot_type = " + std::to_string(slot_type) + " AND slot < " +
            std::to_string(slot_limit) + " ORDER BY slot LIMIT " + std::to_string(slot_limit);
        if (mysql_real_query(impl_->handle, query.data(),
                static_cast<unsigned long>(query.size())) != 0)
            throw mysql_exception(impl_->handle, "Unable to query character item data");
        MYSQL_RES* rows = mysql_store_result(impl_->handle);
        if (rows == nullptr)
            throw mysql_exception(impl_->handle, "Unable to read character item data");
        MYSQL_ROW item_row{};
        while ((item_row = mysql_fetch_row(rows)) != nullptr) {
            auto* item_lengths = mysql_fetch_lengths(rows);
            if (item_lengths == nullptr) {
                mysql_free_result(rows);
                throw mysql_exception(impl_->handle, "Unable to read character item fields");
            }
            const auto slot = static_cast<std::size_t>(number(item_row, item_lengths, 0U));
            if (slot >= destination.size()) continue;
            CharacterItem item{};
            item.item_id = static_cast<std::uint32_t>(number(item_row, item_lengths, 1U));
            item.app = static_cast<std::uint32_t>(number(item_row, item_lengths, 2U));
            item.identific = static_cast<std::uint32_t>(number(item_row, item_lengths, 3U));
            for (unsigned i = 0U; i < 3U; ++i) {
                item.effect_index[i] = static_cast<std::uint32_t>(number(item_row, item_lengths, 4U + i));
                item.effect_value[i] = static_cast<std::uint32_t>(number(item_row, item_lengths, 7U + i));
            }
            item.min = static_cast<std::uint32_t>(number(item_row, item_lengths, 10U));
            item.max = static_cast<std::uint32_t>(number(item_row, item_lengths, 11U));
            item.refine = static_cast<std::uint32_t>(number(item_row, item_lengths, 12U));
            item.time = static_cast<std::uint32_t>(number(item_row, item_lengths, 13U));
            destination[slot] = item;
        }
        mysql_free_result(rows);
    };

    for (auto& character : characters) {
        load_items(character.id, 0U, character.equipment.size(), character.equipment);
        load_items(character.id, 1U, character.inventory.size(), character.inventory);
        // Delphi creates this built-in backpack marker when loading a legacy
        // character whose slot 60 has never been written to the items table.
        if (character.inventory[60U].item_id == 0U) {
            character.inventory[60U].item_id = 5300U;
            character.inventory[60U].app = 5300U;
            character.inventory[60U].refine = 1U;
        }

        const auto load_query = [this, &character](const std::string& sql,
                const char* failure) {
            if (mysql_real_query(impl_->handle, sql.data(),
                    static_cast<unsigned long>(sql.size())) != 0)
                throw mysql_exception(impl_->handle, failure);
            MYSQL_RES* rows = mysql_store_result(impl_->handle);
            if (rows == nullptr) throw mysql_exception(impl_->handle, failure);
            return rows;
        };

        result = load_query(std::string{"SELECT slot, type, item, level FROM skills WHERE owner_charid = "} +
            std::to_string(character.id) + " ORDER BY slot LIMIT 60", "Unable to query character skills");
        while ((row = mysql_fetch_row(result)) != nullptr) {
            auto* lengths = mysql_fetch_lengths(result);
            if (lengths == nullptr) { mysql_free_result(result); throw mysql_exception(impl_->handle, "Unable to read character skills"); }
            const auto slot = static_cast<std::size_t>(number(row, lengths, 0U));
            const auto type = number(row, lengths, 1U);
            const auto item = static_cast<std::uint16_t>(number(row, lengths, 2U));
            const auto level = static_cast<std::uint16_t>(number(row, lengths, 3U));
            const auto target = type == 1U ? slot : slot + 6U;
            if (item != 0U && target < character.skills.size()) character.skills[target] = {item, level};
        }
        mysql_free_result(result);

        result = load_query(std::string{"SELECT slot, item FROM itembars WHERE owner_charid = "} +
            std::to_string(character.id) + " ORDER BY slot LIMIT 32", "Unable to query character item bar");
        while ((row = mysql_fetch_row(result)) != nullptr) {
            auto* lengths = mysql_fetch_lengths(result);
            if (lengths == nullptr) { mysql_free_result(result); throw mysql_exception(impl_->handle, "Unable to read character item bar"); }
            const auto slot = static_cast<std::size_t>(number(row, lengths, 0U));
            if (slot < character.item_bar.size()) character.item_bar[slot] = static_cast<std::uint32_t>(number(row, lengths, 1U));
        }
        mysql_free_result(result);

        result = load_query(std::string{"SELECT buff_index, buff_time FROM buffs WHERE owner_charid = "} +
            std::to_string(character.id) + " LIMIT 60", "Unable to query character buffs");
        std::size_t buff_slot = 0U;
        while ((row = mysql_fetch_row(result)) != nullptr && buff_slot < character.buffs.size()) {
            auto* lengths = mysql_fetch_lengths(result);
            if (lengths == nullptr) { mysql_free_result(result); throw mysql_exception(impl_->handle, "Unable to read character buffs"); }
            character.buffs[buff_slot++] = {number(row, lengths, 0U),
                buff_timestamp(row, lengths, 1U)};
        }
        mysql_free_result(result);

        result = load_query(std::string{"SELECT questid, isdone, req1, req2, req3, req4, req5, updated_at FROM quests WHERE charid = "} +
            std::to_string(character.id), "Unable to query character quests");
        while ((row = mysql_fetch_row(result)) != nullptr) {
            auto* lengths = mysql_fetch_lengths(result);
            if (lengths == nullptr) { mysql_free_result(result); throw mysql_exception(impl_->handle, "Unable to read character quests"); }
            CharacterQuest quest{};
            quest.quest_id = static_cast<std::uint32_t>(number(row, lengths, 0U));
            quest.done = number(row, lengths, 1U) != 0U;
            for (unsigned i = 0U; i < quest.progress.size(); ++i)
                quest.progress[i] = static_cast<std::uint32_t>(number(row, lengths, 2U + i));
            quest.updated_at = number(row, lengths, 7U);
            character.quests.push_back(quest);
        }
        mysql_free_result(result);

        result = load_query(std::string{"SELECT title_index, title_level, title_progress FROM titles WHERE owner_charid = "} +
            std::to_string(character.id), "Unable to query character titles");
        std::size_t title_slot = 0U;
        while ((row = mysql_fetch_row(result)) != nullptr && title_slot < character.titles.size()) {
            auto* lengths = mysql_fetch_lengths(result);
            if (lengths == nullptr) { mysql_free_result(result); throw mysql_exception(impl_->handle, "Unable to read character titles"); }
            character.titles[title_slot++] = CharacterTitle{
                .index = static_cast<std::uint16_t>(number(row, lengths, 0U)),
                .level = static_cast<std::uint8_t>(number(row, lengths, 1U)),
                .progress = static_cast<std::uint16_t>(number(row, lengths, 2U)),
            };
        }
        mysql_free_result(result);
    }
    return characters;
}

void MysqlConnection::save_character_numeric(const std::uint32_t character_id,
        const std::string& token, const std::uint8_t error_count) const {
    if (token.size() > 4U) {
        throw std::invalid_argument{"Character numeric token exceeds Delphi's 4-byte field"};
    }
    impl_->ensure_connected();
    constexpr char query[] =
        "UPDATE characters SET numeric_token = ?, numeric_errors = ? WHERE id = ?";
    MYSQL_STMT* statement = mysql_stmt_init(impl_->handle);
    if (statement == nullptr)
        throw mysql_exception(impl_->handle, "Unable to allocate numeric-token statement");
    const auto fail = [&statement](const char* action) {
        const std::string message = mysql_stmt_error(statement);
        mysql_stmt_close(statement);
        throw std::runtime_error{std::string{action} + ": " + message};
    };
    if (mysql_stmt_prepare(statement, query, sizeof(query) - 1U) != 0)
        fail("Unable to prepare numeric-token update");

    unsigned long token_length = static_cast<unsigned long>(token.size());
    auto mutable_error_count = static_cast<unsigned int>(error_count);
    auto mutable_character_id = character_id;
    MYSQL_BIND parameters[3]{};
    parameters[0].buffer_type = MYSQL_TYPE_STRING;
    parameters[0].buffer = const_cast<char*>(token.data());
    parameters[0].buffer_length = token_length;
    parameters[0].length = &token_length;
    parameters[1].buffer_type = MYSQL_TYPE_LONG;
    parameters[1].buffer = &mutable_error_count;
    parameters[1].is_unsigned = true;
    parameters[2].buffer_type = MYSQL_TYPE_LONG;
    parameters[2].buffer = &mutable_character_id;
    parameters[2].is_unsigned = true;
    if (mysql_stmt_bind_param(statement, parameters) != 0 ||
        mysql_stmt_execute(statement) != 0)
        fail("Unable to persist character numeric token");
    mysql_stmt_close(statement);
}

void MysqlConnection::save_character_deletion(const std::uint32_t character_id,
        const bool deleted, const std::string& delete_time) const {
    impl_->ensure_connected();
    constexpr char query[] =
        "UPDATE characters SET deleted = ?, delete_time = ? WHERE id = ?";
    MYSQL_STMT* statement = mysql_stmt_init(impl_->handle);
    if (statement == nullptr)
        throw mysql_exception(impl_->handle, "Unable to allocate character-deletion statement");
    const auto fail = [&statement](const char* action) {
        const std::string message = mysql_stmt_error(statement);
        mysql_stmt_close(statement);
        throw std::runtime_error{std::string{action} + ": " + message};
    };
    if (mysql_stmt_prepare(statement, query, sizeof(query) - 1U) != 0)
        fail("Unable to prepare character-deletion update");

    auto mutable_deleted = static_cast<unsigned int>(deleted ? 1U : 0U);
    auto mutable_character_id = character_id;
    auto* mutable_delete_time = const_cast<char*>(delete_time.data());
    unsigned long delete_time_length = static_cast<unsigned long>(delete_time.size());
    MYSQL_BIND parameters[3]{};
    parameters[0].buffer_type = MYSQL_TYPE_LONG;
    parameters[0].buffer = &mutable_deleted;
    parameters[0].is_unsigned = true;
    parameters[1].buffer_type = MYSQL_TYPE_STRING;
    parameters[1].buffer = mutable_delete_time;
    parameters[1].buffer_length = delete_time_length;
    parameters[1].length = &delete_time_length;
    parameters[2].buffer_type = MYSQL_TYPE_LONG;
    parameters[2].buffer = &mutable_character_id;
    parameters[2].is_unsigned = true;
    if (mysql_stmt_bind_param(statement, parameters) != 0 ||
        mysql_stmt_execute(statement) != 0)
        fail("Unable to persist character-deletion state");
    mysql_stmt_close(statement);
}

bool MysqlConnection::delete_character(const std::uint32_t character_id) const {
    impl_->ensure_connected();
    const auto execute = [this](const std::string& query, const char* action) {
        if (mysql_real_query(impl_->handle, query.data(),
                static_cast<unsigned long>(query.size())) != 0)
            throw mysql_exception(impl_->handle, action);
    };
    const auto id = std::to_string(character_id);
    execute("START TRANSACTION", "Unable to start character-deletion transaction");
    try {
        execute("SELECT guild_index, player_rank FROM guilds_players WHERE char_index = " +
            id + " LIMIT 1 FOR UPDATE", "Unable to read character guild membership");
        MYSQL_RES* result = mysql_store_result(impl_->handle);
        if (result == nullptr) throw mysql_exception(impl_->handle,
            "Unable to read character guild membership result");
        MYSQL_ROW row = mysql_fetch_row(result);
        const auto guild_id = row != nullptr && row[0] != nullptr
            ? static_cast<std::uint32_t>(std::strtoul(row[0], nullptr, 10)) : 0U;
        const auto guild_rank = row != nullptr && row[1] != nullptr
            ? static_cast<std::uint32_t>(std::strtoul(row[1], nullptr, 10)) : 0U;
        mysql_free_result(result);
        if (guild_id != 0U) {
            const auto guild = std::to_string(guild_id);
            if (guild_rank == 4U) {
                execute("UPDATE characters SET guildindex = 0 WHERE guildindex = " + guild,
                    "Unable to clear guild links before deleting leader");
                execute("DELETE FROM guilds_players WHERE guild_index = " + guild,
                    "Unable to remove guild members before deleting leader");
                execute("UPDATE guilds SET totalmembers = 0 WHERE id = " + guild,
                    "Unable to reset the leader's guild member count");
            } else {
                execute("DELETE FROM guilds_players WHERE guild_index = " + guild +
                    " AND char_index = " + id, "Unable to remove character from guild");
                execute("UPDATE characters SET guildindex = 0 WHERE id = " + id,
                    "Unable to clear character guild link");
                execute("UPDATE guilds SET totalmembers = (SELECT COUNT(*) FROM guilds_players "
                    "WHERE guild_index = " + guild + ") WHERE id = " + guild,
                    "Unable to update guild member count");
            }
        }
        execute("DELETE FROM itembars WHERE owner_charid = " + id,
            "Unable to delete character item bars");
        execute("DELETE FROM items WHERE owner_id = " + id,
            "Unable to delete character items");
        execute("DELETE FROM skills WHERE owner_charid = " + id,
            "Unable to delete character skills");
        execute("DELETE FROM characters WHERE id = " + id,
            "Unable to delete character row");
        execute("COMMIT", "Unable to commit character deletion");
        return true;
    } catch (...) {
        (void)mysql_real_query(impl_->handle, "ROLLBACK", 8U);
        throw;
    }
}

void MysqlConnection::save_character_position(const std::uint32_t character_id,
        const float x, const float y) const {
    impl_->ensure_connected();
    constexpr char query[] = "UPDATE characters SET posx = ?, posy = ? WHERE id = ?";
    MYSQL_STMT* statement = mysql_stmt_init(impl_->handle);
    if (statement == nullptr)
        throw mysql_exception(impl_->handle, "Unable to allocate character-position statement");
    const auto fail = [&statement](const char* action) {
        const std::string message = mysql_stmt_error(statement);
        mysql_stmt_close(statement);
        throw std::runtime_error{std::string{action} + ": " + message};
    };
    if (mysql_stmt_prepare(statement, query, sizeof(query) - 1U) != 0)
        fail("Unable to prepare character-position update");

    auto mutable_x = x;
    auto mutable_y = y;
    auto mutable_character_id = character_id;
    MYSQL_BIND parameters[3]{};
    parameters[0].buffer_type = MYSQL_TYPE_FLOAT;
    parameters[0].buffer = &mutable_x;
    parameters[1].buffer_type = MYSQL_TYPE_FLOAT;
    parameters[1].buffer = &mutable_y;
    parameters[2].buffer_type = MYSQL_TYPE_LONG;
    parameters[2].buffer = &mutable_character_id;
    parameters[2].is_unsigned = true;
    if (mysql_stmt_bind_param(statement, parameters) != 0 ||
        mysql_stmt_execute(statement) != 0)
        fail("Unable to persist character position");
    mysql_stmt_close(statement);
}

void MysqlConnection::save_character_saved_position(const std::uint32_t character_id,
        const float x, const float y) const {
    if (!std::isfinite(x) || !std::isfinite(y) || x == 0.0F || y == 0.0F)
        return;
    impl_->ensure_connected();
    const auto query = "UPDATE characters SET saved_posx = " +
        std::to_string(static_cast<std::int32_t>(std::nearbyint(x))) +
        ", saved_posy = " +
        std::to_string(static_cast<std::int32_t>(std::nearbyint(y))) +
        " WHERE id = " + std::to_string(character_id);
    if (mysql_real_query(impl_->handle, query.data(),
            static_cast<unsigned long>(query.size())) != 0)
        throw mysql_exception(impl_->handle, "Unable to persist saved character position");
}

void MysqlConnection::save_character_rotation(const std::uint32_t character_id,
        const std::uint32_t rotation) const {
    impl_->ensure_connected();
    constexpr char query[] = "UPDATE characters SET rotation = ? WHERE id = ?";
    MYSQL_STMT* statement = mysql_stmt_init(impl_->handle);
    if (statement == nullptr)
        throw mysql_exception(impl_->handle, "Unable to allocate character-rotation statement");
    const auto fail = [&statement](const char* action) {
        const std::string message = mysql_stmt_error(statement);
        mysql_stmt_close(statement);
        throw std::runtime_error{std::string{action} + ": " + message};
    };
    if (mysql_stmt_prepare(statement, query, sizeof(query) - 1U) != 0)
        fail("Unable to prepare character-rotation update");

    auto mutable_rotation = rotation;
    auto mutable_character_id = character_id;
    MYSQL_BIND parameters[2]{};
    parameters[0].buffer_type = MYSQL_TYPE_LONG;
    parameters[0].buffer = &mutable_rotation;
    parameters[0].is_unsigned = true;
    parameters[1].buffer_type = MYSQL_TYPE_LONG;
    parameters[1].buffer = &mutable_character_id;
    parameters[1].is_unsigned = true;
    if (mysql_stmt_bind_param(statement, parameters) != 0 ||
        mysql_stmt_execute(statement) != 0)
        fail("Unable to persist character rotation");
    mysql_stmt_close(statement);
}

bool MysqlConnection::move_character_item(const std::uint32_t character_id,
        const std::uint16_t source_type, const std::uint16_t source_slot,
        const std::uint16_t destination_type, const std::uint16_t destination_slot) const {
    if (source_type > 1U || destination_type > 1U) return false;
    if (source_type == destination_type && source_slot == destination_slot) return true;
    impl_->ensure_connected();

    const auto execute = [this](const std::string& query) {
        if (mysql_real_query(impl_->handle, query.data(),
                static_cast<unsigned long>(query.size())) != 0)
            throw mysql_exception(impl_->handle, "Unable to move character inventory item");
    };
    const auto scalar = [this, &execute](const std::string& query) -> std::uint64_t {
        execute(query);
        MYSQL_RES* result = mysql_store_result(impl_->handle);
        if (result == nullptr)
            throw mysql_exception(impl_->handle, "Unable to read inventory slot state");
        MYSQL_ROW row = mysql_fetch_row(result);
        const auto value = row == nullptr || row[0] == nullptr
            ? 0ULL : static_cast<std::uint64_t>(std::strtoull(row[0], nullptr, 10));
        mysql_free_result(result);
        return value;
    };
    const auto update_slot = [&execute, character_id](const std::uint16_t old_type,
            const std::uint32_t old_slot, const std::uint16_t new_type,
            const std::uint32_t new_slot) {
        const auto query = std::string{"UPDATE items SET slot_type = "} +
            std::to_string(new_type) + ", slot = " + std::to_string(new_slot) +
            " WHERE owner_id = " + std::to_string(character_id) +
            " AND slot_type = " + std::to_string(old_type) + " AND slot = " +
            std::to_string(old_slot);
        execute(query);
    };

    execute("START TRANSACTION");
    try {
        const auto owner = std::to_string(character_id);
        const auto temporary_slot = scalar("SELECT COALESCE(MAX(slot), -1) + 1 FROM items "
            "WHERE owner_id = " + owner + " AND slot_type = " +
            std::to_string(source_type));
        if (temporary_slot > 65535U) {
            execute("ROLLBACK");
            return false;
        }

        update_slot(source_type, source_slot, source_type,
            static_cast<std::uint32_t>(temporary_slot));
        if (mysql_affected_rows(impl_->handle) != 1U) {
            execute("ROLLBACK");
            return false;
        }
        update_slot(destination_type, destination_slot, source_type, source_slot);
        if (mysql_affected_rows(impl_->handle) > 1U)
            throw mysql_exception(impl_->handle, "Duplicate inventory destination slots");
        update_slot(source_type, static_cast<std::uint32_t>(temporary_slot),
            destination_type, destination_slot);
        if (mysql_affected_rows(impl_->handle) != 1U)
            throw mysql_exception(impl_->handle, "Unable to persist inventory slot change");
        execute("COMMIT");
        return true;
    } catch (...) {
        try { execute("ROLLBACK"); } catch (...) {}
        throw;
    }
}

bool MysqlConnection::merge_inventory_stack(const std::uint32_t character_id,
        const std::uint16_t source_slot, const std::uint16_t destination_slot,
        const std::uint16_t source_quantity, const std::uint16_t destination_quantity,
        const std::uint16_t new_source_quantity,
        const std::uint16_t new_destination_quantity) const {
    if (source_slot >= 60U || destination_slot >= 60U || source_slot == destination_slot ||
        source_quantity == 0U || destination_quantity == 0U ||
        new_source_quantity == 0U || new_source_quantity > 1000U ||
        new_destination_quantity > 1000U) return false;
    impl_->ensure_connected();
    const auto execute = [this](const std::string& query) {
        if (mysql_real_query(impl_->handle, query.data(),
                static_cast<unsigned long>(query.size())) != 0)
            throw mysql_exception(impl_->handle, "Unable to merge inventory stacks");
    };
    const auto update_source = std::string{"UPDATE items SET refine = "} +
        std::to_string(new_source_quantity) + " WHERE owner_id = " +
        std::to_string(character_id) + " AND slot_type = 1 AND slot = " +
        std::to_string(source_slot) + " AND refine = " + std::to_string(source_quantity);
    const auto destination_key = std::string{" WHERE owner_id = "} +
        std::to_string(character_id) + " AND slot_type = 1 AND slot = " +
        std::to_string(destination_slot) + " AND refine = " +
        std::to_string(destination_quantity);
    execute("START TRANSACTION");
    try {
        execute(update_source);
        if (mysql_affected_rows(impl_->handle) != 1U)
            throw mysql_exception(impl_->handle, "Inventory source changed during stack merge");
        if (new_destination_quantity == 0U)
            execute("DELETE FROM items" + destination_key);
        else
            execute("UPDATE items SET refine = " + std::to_string(new_destination_quantity) +
                destination_key);
        if (mysql_affected_rows(impl_->handle) != 1U)
            throw mysql_exception(impl_->handle, "Inventory destination changed during stack merge");
        execute("COMMIT");
        return true;
    } catch (...) {
        try { execute("ROLLBACK"); } catch (...) {}
        throw;
    }
}

std::vector<EventItemRecord> MysqlConnection::load_character_event_items(
        const std::uint32_t character_id) const {
    impl_->ensure_connected();
    const auto query = std::string{"SELECT item_id, refine FROM items WHERE owner_id = "} +
        std::to_string(character_id) + " AND slot_type = 17 ORDER BY slot";
    if (mysql_real_query(impl_->handle, query.data(),
            static_cast<unsigned long>(query.size())) != 0)
        throw mysql_exception(impl_->handle, "Unable to query character event rewards");
    MYSQL_RES* result = mysql_store_result(impl_->handle);
    if (result == nullptr)
        throw mysql_exception(impl_->handle, "Unable to read character event rewards");
    std::vector<EventItemRecord> items;
    MYSQL_ROW row{};
    while ((row = mysql_fetch_row(result)) != nullptr) {
        const auto item_id = row[0] == nullptr ? 0UL : std::strtoul(row[0], nullptr, 10);
        const auto quantity = row[1] == nullptr ? 0UL : std::strtoul(row[1], nullptr, 10);
        if (item_id <= (std::numeric_limits<std::uint16_t>::max)() &&
            quantity <= (std::numeric_limits<std::uint16_t>::max)())
            items.push_back({static_cast<std::uint16_t>(item_id),
                static_cast<std::uint16_t>(quantity)});
    }
    mysql_free_result(result);
    return items;
}

void MysqlConnection::save_character_item_bar_slot(const std::uint32_t character_id,
        const std::uint8_t slot, const std::uint32_t item) const {
    if (slot >= 32U) throw std::out_of_range{"Character item-bar slot is out of range"};
    impl_->ensure_connected();
    const auto owner = std::to_string(character_id);
    const auto slot_value = std::to_string(slot);
    const auto execute = [this](const std::string& query) {
        if (mysql_real_query(impl_->handle, query.data(),
                static_cast<unsigned long>(query.size())) != 0)
            throw mysql_exception(impl_->handle, "Unable to save character item bar");
    };
    execute("START TRANSACTION");
    try {
        execute("DELETE FROM itembars WHERE owner_charid = " + owner +
            " AND slot = " + slot_value);
        if (item != 0U) {
            execute("INSERT INTO itembars (owner_charid, slot, item) VALUES (" +
                owner + ", " + slot_value + ", " + std::to_string(item) + ")");
        }
        execute("COMMIT");
    } catch (...) {
        try { execute("ROLLBACK"); } catch (...) {}
        throw;
    }
}

void MysqlConnection::save_character_attributes(const std::uint32_t character_id,
        const std::array<std::uint16_t, 6>& attributes) const {
    impl_->ensure_connected();
    constexpr char query[] =
        "UPDATE characters SET strength = ?, agility = ?, intelligence = ?, "
        "constitution = ?, luck = ?, status = ? WHERE id = ?";
    MYSQL_STMT* statement = mysql_stmt_init(impl_->handle);
    if (statement == nullptr)
        throw mysql_exception(impl_->handle, "Unable to allocate character attributes statement");
    const auto fail = [&statement](const char* action) {
        const std::string message = mysql_stmt_error(statement);
        mysql_stmt_close(statement);
        throw std::runtime_error{std::string{action} + ": " + message};
    };
    if (mysql_stmt_prepare(statement, query, sizeof(query) - 1U) != 0)
        fail("Unable to prepare character attributes update");

    auto mutable_attributes = attributes;
    auto mutable_character_id = character_id;
    MYSQL_BIND parameters[7]{};
    for (unsigned i = 0U; i < mutable_attributes.size(); ++i) {
        parameters[i].buffer_type = MYSQL_TYPE_SHORT;
        parameters[i].buffer = &mutable_attributes[i];
        parameters[i].is_unsigned = true;
    }
    parameters[6].buffer_type = MYSQL_TYPE_LONG;
    parameters[6].buffer = &mutable_character_id;
    parameters[6].is_unsigned = true;
    if (mysql_stmt_bind_param(statement, parameters) != 0 ||
        mysql_stmt_execute(statement) != 0)
        fail("Unable to persist character attributes");
    mysql_stmt_close(statement);
}

void MysqlConnection::learn_character_skill(const std::uint32_t character_id,
        const std::uint16_t slot, const std::uint8_t type,
        const std::uint16_t skill_id, const std::uint16_t level,
        const std::array<std::uint16_t, 6>& attributes,
        const std::uint16_t skill_points, const std::uint64_t gold,
        const std::vector<std::pair<std::uint8_t, std::uint32_t>>& item_bar_updates) const {
    impl_->ensure_connected();
    const auto execute = [this](const std::string& query, const char* action) {
        if (mysql_real_query(impl_->handle, query.data(),
                static_cast<unsigned long>(query.size())) != 0)
            throw mysql_exception(impl_->handle, action);
    };
    const auto character = std::to_string(character_id);
    execute("START TRANSACTION", "Unable to start skill-learning transaction");
    try {
        execute("UPDATE characters SET strength = " + std::to_string(attributes[0]) +
            ", agility = " + std::to_string(attributes[1]) +
            ", intelligence = " + std::to_string(attributes[2]) +
            ", constitution = " + std::to_string(attributes[3]) +
            ", luck = " + std::to_string(attributes[4]) +
            ", status = " + std::to_string(attributes[5]) +
            ", skillpoint = " + std::to_string(skill_points) +
            ", gold = " + std::to_string(gold) + " WHERE id = " + character,
            "Unable to persist skill costs");

        const auto skill_where = " WHERE owner_charid = " + character +
            " AND slot = " + std::to_string(slot) + " AND type = " +
            std::to_string(type);
        execute("UPDATE skills SET level = " + std::to_string(level) + skill_where,
            "Unable to update learned skill level");
        if (mysql_affected_rows(impl_->handle) == 0U) {
            execute("INSERT INTO skills (owner_charid, slot, item, level, type) VALUES (" +
                character + ", " + std::to_string(slot) + ", " +
                std::to_string(skill_id) + ", " + std::to_string(level) + ", " +
                std::to_string(type) + ")", "Unable to insert learned skill");
        }
        for (const auto& [bar_slot, item] : item_bar_updates) {
            execute("UPDATE itembars SET item = " + std::to_string(item) +
                " WHERE owner_charid = " + character + " AND slot = " +
                std::to_string(bar_slot), "Unable to update learned skill shortcut");
        }
        execute("COMMIT", "Unable to commit skill-learning transaction");
    } catch (...) {
        (void)mysql_real_query(impl_->handle, "ROLLBACK", 8U);
        throw;
    }
}

void MysqlConnection::reset_character_skills(const std::uint32_t character_id,
        const std::vector<CharacterSkillPlacement>& skills,
        const std::uint16_t skill_points, const std::uint64_t gold) const {
    impl_->ensure_connected();
    const auto execute = [this](const std::string& query, const char* action) {
        if (mysql_real_query(impl_->handle, query.data(),
                static_cast<unsigned long>(query.size())) != 0)
            throw mysql_exception(impl_->handle, action);
    };
    const auto character = std::to_string(character_id);
    execute("START TRANSACTION", "Unable to start skill-reset transaction");
    try {
        execute("UPDATE characters SET skillpoint = " + std::to_string(skill_points) +
            ", gold = " + std::to_string(gold) + " WHERE id = " + character,
            "Unable to persist skill-reset balance");
        execute("DELETE FROM skills WHERE owner_charid = " + character,
            "Unable to clear character skills");
        for (const auto& skill : skills) {
            execute("INSERT INTO skills (owner_charid, slot, item, level, type) VALUES (" +
                character + ", " + std::to_string(skill.slot) + ", " +
                std::to_string(skill.item) + ", " + std::to_string(skill.level) + ", " +
                std::to_string(skill.type) + ")", "Unable to restore initial character skill");
        }
        execute("DELETE FROM itembars WHERE owner_charid = " + character,
            "Unable to clear character item bars");
        execute("COMMIT", "Unable to commit skill-reset transaction");
    } catch (...) {
        (void)mysql_real_query(impl_->handle, "ROLLBACK", 8U);
        throw;
    }
}

void MysqlConnection::remove_character_buff(const std::uint32_t character_id,
        const std::uint16_t buff_index) const {
    impl_->ensure_connected();
    const auto query = "DELETE FROM buffs WHERE owner_charid = " +
        std::to_string(character_id) + " AND buff_index = " +
        std::to_string(buff_index);
    if (mysql_real_query(impl_->handle, query.data(),
            static_cast<unsigned long>(query.size())) != 0) {
        throw mysql_exception(impl_->handle, "Unable to remove character buff");
    }
}

void MysqlConnection::save_character_buffs(const std::uint32_t character_id,
        const std::array<std::array<std::uint64_t, 2>, 60>& buffs) const {
    impl_->ensure_connected();
    const auto execute = [this](const std::string& query, const char* action) {
        if (mysql_real_query(impl_->handle, query.data(),
                static_cast<unsigned long>(query.size())) != 0)
            throw mysql_exception(impl_->handle, action);
    };
    const auto character = std::to_string(character_id);
    execute("START TRANSACTION", "Unable to start character-buff transaction");
    try {
        execute("DELETE FROM buffs WHERE owner_charid = " + character,
            "Unable to clear saved character buffs");
        for (const auto& buff : buffs) {
            if (buff[0] == 0U) continue;
            execute("INSERT INTO buffs (buff_index, buff_time, owner_charid) VALUES (" +
                std::to_string(buff[0]) + ", FROM_UNIXTIME(" +
                std::to_string(buff[1]) + "), " + character + ")",
                "Unable to save character buff");
        }
        execute("COMMIT", "Unable to commit character-buff transaction");
    } catch (...) {
        (void)mysql_real_query(impl_->handle, "ROLLBACK", 8U);
        throw;
    }
}

void MysqlConnection::craft_character_items(const std::uint32_t character_id,
        const std::uint64_t gold,
        const std::vector<std::pair<std::uint16_t, CharacterItem>>& updates) const {
    std::vector<CharacterItemPlacement> placements;
    placements.reserve(updates.size());
    for (const auto& [slot, item] : updates)
        placements.push_back({1U, slot, item});
    save_character_items(character_id, gold, placements);
}

void MysqlConnection::save_character_items(const std::uint32_t character_id,
        const std::uint64_t gold,
        const std::vector<CharacterItemPlacement>& updates,
        const std::vector<std::uint16_t>& buffs_to_remove,
        const std::optional<std::pair<std::uint32_t, std::uint32_t>>& hp_mp,
        const std::optional<std::pair<std::uint32_t, std::uint32_t>>& account_cash,
        const std::optional<std::array<std::array<std::uint64_t, 2>, 60>>& buffs,
        const std::optional<CharacterProgression>& progression,
        const std::vector<std::pair<std::uint16_t, std::uint16_t>>& event_rewards,
        const std::vector<std::pair<std::uint16_t, std::uint16_t>>& event_claims,
        const std::optional<std::uint64_t>& last_diary_event,
        const std::vector<CharacterTitle>& titles_to_add,
        const std::optional<std::uint32_t>& account_storage_owner,
        const std::optional<std::uint32_t>& honor) const {
    impl_->ensure_connected();
    const auto execute = [this](const std::string& query, const char* action) {
        if (mysql_real_query(impl_->handle, query.data(),
                static_cast<unsigned long>(query.size())) != 0)
            throw mysql_exception(impl_->handle, action);
    };
    const auto character = std::to_string(character_id);
    execute("START TRANSACTION", "Unable to start item-crafting transaction");
    try {
        if (account_storage_owner.has_value()) {
            execute("SELECT id FROM accounts WHERE id = " +
                std::to_string(*account_storage_owner) + " FOR UPDATE",
                "Unable to lock account storage owner");
            MYSQL_RES* owner = mysql_store_result(impl_->handle);
            if (owner == nullptr)
                throw mysql_exception(impl_->handle, "Unable to verify account storage owner");
            const bool owner_exists = mysql_num_rows(owner) != 0U;
            mysql_free_result(owner);
            if (!owner_exists)
                throw std::runtime_error{"Account storage owner does not exist"};
        }
        auto character_values = "gold = " + std::to_string(gold);
        if (honor.has_value())
            character_values += ", honor = " + std::to_string(*honor);
        if (hp_mp.has_value())
            character_values += ", curhp = " + std::to_string(hp_mp->first) +
                ", curmp = " + std::to_string(hp_mp->second);
        execute("UPDATE characters SET " + character_values + " WHERE id = " +
            character, "Unable to save character item state");
        if (account_cash.has_value())
            execute("UPDATE accounts SET cash = " +
                std::to_string(account_cash->second) + " WHERE id = " +
                std::to_string(account_cash->first),
                "Unable to save account cash from item use");
        for (const auto& placement : updates) {
            const auto slot = placement.slot;
            const auto& item = placement.item;
            const auto item_owner = placement.slot_type == 2U &&
                    account_storage_owner.has_value()
                ? std::to_string(*account_storage_owner) : character;
            const auto location = " WHERE owner_id = " + item_owner +
                " AND slot_type = " + std::to_string(placement.slot_type) +
                " AND slot = " + std::to_string(slot);
            if (item.item_id == 0U) {
                execute("DELETE FROM items" + location,
                    "Unable to consume crafting ingredient");
                continue;
            }

            execute("SELECT item_id FROM items" + location + " FOR UPDATE",
                "Unable to lock crafting inventory slot");
            MYSQL_RES* result = mysql_store_result(impl_->handle);
            if (result == nullptr)
                throw mysql_exception(impl_->handle, "Unable to read crafting inventory slot");
            const bool exists = mysql_num_rows(result) != 0U;
            mysql_free_result(result);

            const auto values = "item_id = " + std::to_string(item.item_id) +
                ", app = " + std::to_string(item.app) +
                ", identific = " + std::to_string(item.identific) +
                ", effect1_index = " + std::to_string(item.effect_index[0]) +
                ", effect1_value = " + std::to_string(item.effect_value[0]) +
                ", effect2_index = " + std::to_string(item.effect_index[1]) +
                ", effect2_value = " + std::to_string(item.effect_value[1]) +
                ", effect3_index = " + std::to_string(item.effect_index[2]) +
                ", effect3_value = " + std::to_string(item.effect_value[2]) +
                ", min = " + std::to_string(item.min) +
                ", max = " + std::to_string(item.max) +
                ", refine = " + std::to_string(item.refine) +
                ", time = " + std::to_string(item.time);
            if (exists) {
                execute("UPDATE items SET " + values + location,
                    "Unable to save crafted inventory item");
            } else {
                execute("INSERT INTO items (slot_type, owner_id, slot, item_id, app, "
                    "identific, effect1_index, effect1_value, effect2_index, effect2_value, "
                    "effect3_index, effect3_value, min, max, refine, time) VALUES (" +
                    std::to_string(placement.slot_type) + ", " +
                    item_owner + ", " + std::to_string(slot) + ", " +
                    std::to_string(item.item_id) + ", " + std::to_string(item.app) + ", " +
                    std::to_string(item.identific) + ", " +
                    std::to_string(item.effect_index[0]) + ", " +
                    std::to_string(item.effect_value[0]) + ", " +
                    std::to_string(item.effect_index[1]) + ", " +
                    std::to_string(item.effect_value[1]) + ", " +
                    std::to_string(item.effect_index[2]) + ", " +
                    std::to_string(item.effect_value[2]) + ", " +
                    std::to_string(item.min) + ", " + std::to_string(item.max) + ", " +
                    std::to_string(item.refine) + ", " + std::to_string(item.time) + ")",
                    "Unable to insert character item");
            }
        }
        for (const auto& [item_id, quantity] : event_claims) {
            execute("DELETE FROM items WHERE slot_type = 17 AND owner_id = " + character +
                " AND item_id = " + std::to_string(item_id) + " AND refine = " +
                std::to_string(quantity) + " LIMIT 1",
                "Unable to remove claimed character event reward");
            if (mysql_affected_rows(impl_->handle) != 1U)
                throw mysql_exception(impl_->handle,
                    "Character event reward changed before claim");
        }
        for (const auto buff_index : buffs_to_remove)
            execute("DELETE FROM buffs WHERE owner_charid = " + character +
                " AND buff_index = " + std::to_string(buff_index),
                "Unable to remove item-associated character buff");
        if (buffs.has_value()) {
            execute("DELETE FROM buffs WHERE owner_charid = " + character,
                "Unable to replace saved character buffs");
            for (const auto& buff : *buffs) {
                if (buff[0] == 0U) continue;
                execute("INSERT INTO buffs (buff_index, buff_time, owner_charid) VALUES (" +
                    std::to_string(buff[0]) + ", FROM_UNIXTIME(" +
                    std::to_string(buff[1]) + "), " + character + ")",
                    "Unable to save replacement character buff");
            }
        }
        if (progression.has_value()) {
            const auto& value = *progression;
            execute("UPDATE characters SET classinfo = " +
                std::to_string(value.class_info) + ", level = " +
                std::to_string(value.level) + ", skillpoint = " +
                std::to_string(value.skill_points) + ", strength = " +
                std::to_string(value.attributes[0]) + ", agility = " +
                std::to_string(value.attributes[1]) + ", intelligence = " +
                std::to_string(value.attributes[2]) + ", constitution = " +
                std::to_string(value.attributes[3]) + ", luck = " +
                std::to_string(value.attributes[4]) + ", status = " +
                std::to_string(value.attributes[5]) + ", experience = " +
                std::to_string(value.experience) + ", gold = " +
                std::to_string(value.gold) + ", curhp = " +
                std::to_string(value.current_hp) + ", curmp = " +
                std::to_string(value.current_mp) + " WHERE id = " + character,
                "Unable to save character level progression");
        }
        for (const auto& [item_id, quantity] : event_rewards)
            execute("INSERT INTO items (slot_type, owner_id, item_id, refine, slot) VALUES (17, " +
                character + ", " + std::to_string(item_id) + ", " +
                std::to_string(quantity) + ", 0)",
                "Unable to queue character level event reward");
        if (last_diary_event.has_value())
            execute("UPDATE characters SET last_diary_event = " +
                std::to_string(*last_diary_event) + " WHERE id = " + character,
                "Unable to save daily event reward time");
        for (const auto& title : titles_to_add)
            execute("INSERT INTO titles (owner_charid, title_index, title_level, "
                "title_progress) VALUES (" + character + ", " +
                std::to_string(title.index) + ", " + std::to_string(title.level) +
                ", " + std::to_string(title.progress) + ")",
                "Unable to save item-granted character title");
        execute("COMMIT", "Unable to commit item-crafting transaction");
    } catch (...) {
        (void)mysql_real_query(impl_->handle, "ROLLBACK", 8U);
        throw;
    }
}

void MysqlConnection::set_account_active(const std::uint32_t account_id,
        const bool active) const {
    impl_->ensure_connected();
    const auto query = std::string{"UPDATE accounts SET isactive = "} +
        (active ? "1" : "0") + " WHERE id = " + std::to_string(account_id);
    if (mysql_real_query(impl_->handle, query.data(),
            static_cast<unsigned long>(query.size())) != 0) {
        throw mysql_exception(impl_->handle, "Unable to update account session status");
    }
}

std::uint64_t MysqlConnection::count_characters(const std::uint32_t account_id) const {
    impl_->ensure_connected();
    constexpr char query[] =
        "SELECT COUNT(*) FROM characters WHERE owner_accid = ?";
    MYSQL_STMT* statement = mysql_stmt_init(impl_->handle);
    if (statement == nullptr) {
        throw mysql_exception(impl_->handle, "Unable to allocate MySQL statement");
    }
    if (mysql_stmt_prepare(statement, query, sizeof(query) - 1U) != 0) {
        const std::string message = mysql_stmt_error(statement);
        mysql_stmt_close(statement);
        throw std::runtime_error{"Unable to prepare character count query: " + message};
    }

    auto account_id_parameter = account_id;
    MYSQL_BIND parameter{};
    parameter.buffer_type = MYSQL_TYPE_LONG;
    parameter.buffer = &account_id_parameter;
    parameter.is_unsigned = true;
    if (mysql_stmt_bind_param(statement, &parameter) != 0 ||
        mysql_stmt_execute(statement) != 0) {
        const std::string message = mysql_stmt_error(statement);
        mysql_stmt_close(statement);
        throw std::runtime_error{"Unable to count account characters: " + message};
    }

    std::uint64_t count{};
    MYSQL_BIND result{};
    result.buffer_type = MYSQL_TYPE_LONGLONG;
    result.buffer = &count;
    result.is_unsigned = true;
    if (mysql_stmt_bind_result(statement, &result) != 0 ||
        mysql_stmt_store_result(statement) != 0 || mysql_stmt_fetch(statement) != 0) {
        const std::string message = mysql_stmt_error(statement);
        mysql_stmt_close(statement);
        throw std::runtime_error{"Unable to read character count: " + message};
    }
    mysql_stmt_close(statement);
    return count;
}

std::optional<std::uint32_t> MysqlConnection::create_character(
        const std::uint32_t account_id, const NewCharacterData& data) const {
    impl_->ensure_connected();
    const auto execute = [this](const std::string& query, const char* action) {
        if (mysql_real_query(impl_->handle, query.data(),
                static_cast<unsigned long>(query.size())) != 0)
            throw mysql_exception(impl_->handle, action);
    };
    const auto escaped_name = [&] {
        std::string escaped(data.character.name.size() * 2U + 1U, '\0');
        const auto length = mysql_real_escape_string(impl_->handle, escaped.data(),
            data.character.name.data(),
            static_cast<unsigned long>(data.character.name.size()));
        escaped.resize(length);
        return escaped;
    }();
    const auto owner = std::to_string(account_id);
    const auto slot = std::to_string(data.character.slot);
    execute("START TRANSACTION", "Unable to start character creation transaction");
    try {
        execute("SELECT id FROM accounts WHERE id = " + owner + " FOR UPDATE",
            "Unable to lock the owner account");
        MYSQL_RES* result = mysql_store_result(impl_->handle);
        if (result == nullptr) throw mysql_exception(impl_->handle,
            "Unable to verify the owner account");
        const bool account_exists = mysql_num_rows(result) != 0U;
        mysql_free_result(result);
        if (!account_exists) {
            execute("ROLLBACK", "Unable to roll back character creation");
            return std::nullopt;
        }

        execute("SELECT slot FROM characters WHERE owner_accid = " + owner +
            " FOR UPDATE", "Unable to inspect account character slots");
        result = mysql_store_result(impl_->handle);
        if (result == nullptr) throw mysql_exception(impl_->handle,
            "Unable to read account character slots");
        bool slot_taken = false;
        const auto character_count = mysql_num_rows(result);
        MYSQL_ROW row{};
        while ((row = mysql_fetch_row(result)) != nullptr)
            if (row[0] != nullptr && std::strtoul(row[0], nullptr, 10) == data.character.slot)
                slot_taken = true;
        mysql_free_result(result);
        if (character_count >= 3U || slot_taken) {
            execute("ROLLBACK", "Unable to roll back character creation");
            return std::nullopt;
        }

        execute("SELECT id FROM characters WHERE name = '" + escaped_name + "' LIMIT 1",
            "Unable to verify character name");
        result = mysql_store_result(impl_->handle);
        if (result == nullptr) throw mysql_exception(impl_->handle,
            "Unable to read character name result");
        const bool name_taken = mysql_num_rows(result) != 0U;
        mysql_free_result(result);
        if (name_taken) {
            execute("ROLLBACK", "Unable to roll back character creation");
            return std::nullopt;
        }

        const auto& character = data.character;
        const auto attribute = [&character](const std::size_t index) {
            return std::to_string(character.attributes[index]);
        };
        const auto size = [&character](const std::size_t index) {
            return std::to_string(character.sizes[index]);
        };
        const auto timestamp = std::to_string(character.creation_time);
        const auto insert_character = "INSERT INTO characters (owner_accid, name, slot, classinfo, "
            "strength, agility, intelligence, constitution, luck, status, curhp, curmp, "
            "altura, tronco, perna, corpo, "
            "experience, level, gold, posx, posy, creationtime, pranevcnt, last_diary_event, "
            "numeric_errors, numeric_token) VALUES (" +
            owner + ", '" + escaped_name + "', " + slot + ", " +
            std::to_string(character.class_info) + ", " + attribute(0U) + ", " +
            attribute(1U) + ", " + attribute(2U) + ", " + attribute(3U) + ", " +
            attribute(4U) + ", " + attribute(5U) + ", " +
            std::to_string(character.current_hp) + ", " +
            std::to_string(character.current_mp) + ", " + size(0U) + ", " +
            size(1U) + ", " + size(2U) + ", " + size(3U) + ", " +
            std::to_string(character.experience) + ", " + std::to_string(character.level) + ", " +
            std::to_string(character.gold) + ", " + std::to_string(character.position_x) + ", " +
            std::to_string(character.position_y) + ", " + timestamp + ", 0, " + timestamp +
            ", 0, '')";
        execute(insert_character, "Unable to insert character row");
        const auto character_id = static_cast<std::uint32_t>(mysql_insert_id(impl_->handle));
        if (character_id == 0U)
            throw std::runtime_error{"MySQL did not return the new character ID"};

        for (const auto& placement : data.items) {
            const auto& item = placement.item;
            const auto insert_item = "INSERT INTO items (slot_type, owner_id, slot, item_id, app, "
                "effect1_index, effect1_value, effect2_index, effect2_value, effect3_index, "
                "effect3_value, min, max, refine, time) VALUES (" +
                std::to_string(placement.slot_type) + ", " + std::to_string(character_id) + ", " +
                std::to_string(placement.slot) + ", " + std::to_string(item.item_id) + ", " +
                std::to_string(item.app) + ", " + std::to_string(item.effect_index[0]) + ", " +
                std::to_string(item.effect_value[0]) + ", " +
                std::to_string(item.effect_index[1]) + ", " +
                std::to_string(item.effect_value[1]) + ", " +
                std::to_string(item.effect_index[2]) + ", " +
                std::to_string(item.effect_value[2]) + ", " + std::to_string(item.min) + ", " +
                std::to_string(item.max) + ", " + std::to_string(item.refine) + ", " +
                std::to_string(item.time) + ")";
            execute(insert_item, "Unable to insert initial character item");
        }
        for (const auto& skill : data.skills) {
            execute("INSERT INTO skills (owner_charid, slot, item, level, type) VALUES (" +
                std::to_string(character_id) + ", " + std::to_string(skill.slot) + ", " +
                std::to_string(skill.item) + ", " + std::to_string(skill.level) + ", " +
                std::to_string(skill.type) + ")", "Unable to insert initial character skill");
        }
        for (std::size_t bar_slot = 0U; bar_slot < data.item_bar.size(); ++bar_slot) {
            if (data.item_bar[bar_slot] == 0U) continue;
            execute("INSERT INTO itembars (owner_charid, slot, item) VALUES (" +
                std::to_string(character_id) + ", " + std::to_string(bar_slot) + ", " +
                std::to_string(data.item_bar[bar_slot]) + ")",
                "Unable to insert initial character item bar entry");
        }
        execute("COMMIT", "Unable to commit character creation");
        return character_id;
    } catch (...) {
        (void)mysql_real_query(impl_->handle, "ROLLBACK", 8U);
        throw;
    }
}

void MysqlConnection::save_account_token(const std::string& username,
        const std::string& token, const std::int64_t creation_time,
        const std::uint64_t premium_time) const {
    impl_->ensure_connected();
    constexpr char query[] =
        "UPDATE accounts SET last_token = ?, last_token_creation_time = ?, "
        "premium_time = ? WHERE username = ?";
    MYSQL_STMT* statement = mysql_stmt_init(impl_->handle);
    if (statement == nullptr) {
        throw mysql_exception(impl_->handle, "Unable to allocate MySQL statement");
    }
    if (mysql_stmt_prepare(statement, query, sizeof(query) - 1U) != 0) {
        const std::string message = mysql_stmt_error(statement);
        mysql_stmt_close(statement);
        throw std::runtime_error{"Unable to prepare token update: " + message};
    }

    std::int64_t creation = creation_time;
    std::uint64_t premium = premium_time;
    unsigned long token_length = static_cast<unsigned long>(token.size());
    unsigned long username_length = static_cast<unsigned long>(username.size());
    MYSQL_BIND parameters[4]{};
    parameters[0].buffer_type = MYSQL_TYPE_STRING;
    parameters[0].buffer = const_cast<char*>(token.data());
    parameters[0].buffer_length = token_length;
    parameters[0].length = &token_length;
    parameters[1].buffer_type = MYSQL_TYPE_LONGLONG;
    parameters[1].buffer = &creation;
    parameters[1].is_unsigned = false;
    parameters[2].buffer_type = MYSQL_TYPE_LONGLONG;
    parameters[2].buffer = &premium;
    parameters[2].is_unsigned = true;
    parameters[3].buffer_type = MYSQL_TYPE_STRING;
    parameters[3].buffer = const_cast<char*>(username.data());
    parameters[3].buffer_length = username_length;
    parameters[3].length = &username_length;
    if (mysql_stmt_bind_param(statement, parameters) != 0 ||
        mysql_stmt_execute(statement) != 0) {
        const std::string message = mysql_stmt_error(statement);
        mysql_stmt_close(statement);
        throw std::runtime_error{"Unable to save account token: " + message};
    }
    mysql_stmt_close(statement);
}

void MysqlConnection::clear_expired_ban(const std::string& username) const {
    impl_->ensure_connected();
    constexpr char query[] =
        "UPDATE accounts SET account_status = 0, ban_days = 0 WHERE username = ?";
    MYSQL_STMT* statement = mysql_stmt_init(impl_->handle);
    if (statement == nullptr) {
        throw mysql_exception(impl_->handle, "Unable to allocate MySQL statement");
    }
    if (mysql_stmt_prepare(statement, query, sizeof(query) - 1U) != 0) {
        const std::string message = mysql_stmt_error(statement);
        mysql_stmt_close(statement);
        throw std::runtime_error{"Unable to prepare expired-ban update: " + message};
    }

    unsigned long username_length = static_cast<unsigned long>(username.size());
    MYSQL_BIND parameter{};
    parameter.buffer_type = MYSQL_TYPE_STRING;
    parameter.buffer = const_cast<char*>(username.data());
    parameter.buffer_length = username_length;
    parameter.length = &username_length;
    if (mysql_stmt_bind_param(statement, &parameter) != 0 ||
        mysql_stmt_execute(statement) != 0) {
        const std::string message = mysql_stmt_error(statement);
        mysql_stmt_close(statement);
        throw std::runtime_error{"Unable to clear expired account ban: " + message};
    }
    mysql_stmt_close(statement);
}

} // namespace aika::database
