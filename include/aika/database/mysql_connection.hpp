#pragma once

#include "aika/config/server_config.hpp"

#include <array>
#include <cstddef>
#include <memory>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace aika::database {

struct ColumnMetadata final {
    std::string table;
    std::string name;
    std::string type;
    bool nullable{};
    bool primary_key{};
};

struct CharacterItem final {
    std::uint32_t item_id{};
    std::uint32_t app{};
    std::uint32_t refine{};
    std::uint32_t identific{};
    std::array<std::uint32_t, 3> effect_index{};
    std::array<std::uint32_t, 3> effect_value{};
    std::uint32_t min{};
    std::uint32_t max{};
    std::uint32_t time{};
};

struct AccountRecord final {
    std::uint32_t id{};
    std::string password_hash;
    std::string last_token;
    std::int64_t last_token_creation_time{};
    std::uint32_t nation{};
    std::uint32_t account_status{};
    std::uint8_t account_type{};
    std::uint64_t premium_time{};
    std::uint64_t storage_gold{};
    std::uint32_t cash{};
    std::uint32_t ban_days{};
    std::array<CharacterItem, 86> storage_items{};
};

struct CharacterQuest final {
    std::uint32_t quest_id{};
    bool done{};
    std::array<std::uint32_t, 5> progress{};
    std::uint64_t updated_at{};
};

struct CharacterTitle final {
    std::uint16_t index{};
    std::uint8_t level{};
    std::uint16_t progress{};
};

struct CharacterProgression final {
    std::uint16_t class_info{};
    std::uint16_t level{};
    std::uint16_t skill_points{};
    std::array<std::uint16_t, 6> attributes{};
    std::uint64_t experience{};
    std::uint64_t gold{};
    std::uint32_t current_hp{};
    std::uint32_t current_mp{};
};

struct CharacterRecord final {
    std::uint32_t id{};
    std::uint32_t slot{};
    std::string name;
    std::uint16_t class_info{};
    std::array<std::uint16_t, 6> attributes{};
    std::array<std::uint8_t, 4> sizes{};
    std::uint64_t experience{};
    std::uint64_t gold{};
    std::uint16_t level{};
    std::uint16_t skill_points{};
    std::uint32_t current_hp{};
    std::uint32_t current_mp{};
    std::uint32_t honor{};
    std::uint32_t kill_points{};
    std::uint32_t infamy{};
    std::uint32_t guild_id{};
    std::uint32_t creation_time{};
    std::uint32_t login_time{};
    std::uint32_t move_speed{};
    std::uint32_t rotation{};
    std::uint32_t logged_time{};
    bool player_kill{};
    float position_x{};
    float position_y{};
    float saved_position_x{};
    float saved_position_y{};
    std::uint16_t active_title{};
    std::uint64_t last_diary_event{};
    bool deleted{};
    std::string delete_time;
    std::uint8_t numeric_errors{};
    std::string numeric_token;
    std::array<CharacterItem, 16> equipment{};
    std::array<CharacterItem, 64> inventory{};
    std::array<std::array<std::uint16_t, 2>, 46> skills{};
    std::array<std::uint32_t, 32> item_bar{};
    std::array<std::array<std::uint64_t, 2>, 60> buffs{};
    std::vector<CharacterQuest> quests;
    std::array<CharacterTitle, 96> titles{};
};

struct CharacterItemPlacement final {
    std::uint8_t slot_type{};
    std::uint16_t slot{};
    CharacterItem item{};
};

struct EventItemRecord final {
    std::uint16_t item_id{};
    std::uint16_t quantity{};
};

struct CharacterSkillPlacement final {
    std::uint16_t slot{};
    std::uint16_t item{};
    std::uint16_t level{};
    std::uint8_t type{};
};

struct NewCharacterData final {
    CharacterRecord character;
    std::vector<CharacterItemPlacement> items;
    std::vector<CharacterSkillPlacement> skills;
    std::array<std::uint32_t, 32> item_bar{};
};

class MysqlConnection final {
public:
    explicit MysqlConnection(const config::DatabaseConfig& config);
    ~MysqlConnection();
    MysqlConnection(MysqlConnection&&) noexcept;
    MysqlConnection& operator=(MysqlConnection&&) noexcept;
    MysqlConnection(const MysqlConnection&) = delete;
    MysqlConnection& operator=(const MysqlConnection&) = delete;

    [[nodiscard]] bool connected() const noexcept;
    [[nodiscard]] std::vector<ColumnMetadata> inspect_schema() const;
    [[nodiscard]] std::optional<AccountRecord> find_account(
        const std::string& username) const;
    [[nodiscard]] std::vector<CharacterRecord> load_characters(
        std::uint32_t account_id, bool include_details = false) const;
    void save_character_numeric(std::uint32_t character_id,
        const std::string& token, std::uint8_t error_count) const;
    void save_character_deletion(std::uint32_t character_id, bool deleted,
        const std::string& delete_time) const;
    [[nodiscard]] bool delete_character(std::uint32_t character_id) const;
    void save_character_position(std::uint32_t character_id, float x, float y) const;
    void save_character_saved_position(std::uint32_t character_id,
        float x, float y) const;
    void save_character_rotation(std::uint32_t character_id,
        std::uint32_t rotation) const;
    [[nodiscard]] bool move_character_item(std::uint32_t character_id,
        std::uint16_t source_type, std::uint16_t source_slot,
        std::uint16_t destination_type, std::uint16_t destination_slot) const;
    [[nodiscard]] bool merge_inventory_stack(std::uint32_t character_id,
        std::uint16_t source_slot, std::uint16_t destination_slot,
        std::uint16_t source_quantity, std::uint16_t destination_quantity,
        std::uint16_t new_source_quantity, std::uint16_t new_destination_quantity) const;
    [[nodiscard]] std::vector<EventItemRecord> load_character_event_items(
        std::uint32_t character_id) const;
    void save_character_item_bar_slot(std::uint32_t character_id,
        std::uint8_t slot, std::uint32_t item) const;
    void save_character_attributes(std::uint32_t character_id,
        const std::array<std::uint16_t, 6>& attributes) const;
    void learn_character_skill(std::uint32_t character_id, std::uint16_t slot,
        std::uint8_t type, std::uint16_t skill_id, std::uint16_t level,
        const std::array<std::uint16_t, 6>& attributes,
        std::uint16_t skill_points, std::uint64_t gold,
        const std::vector<std::pair<std::uint8_t, std::uint32_t>>& item_bar_updates) const;
    void reset_character_skills(std::uint32_t character_id,
        const std::vector<CharacterSkillPlacement>& skills,
        std::uint16_t skill_points, std::uint64_t gold) const;
    void remove_character_buff(std::uint32_t character_id,
        std::uint16_t buff_index) const;
    void save_character_buffs(std::uint32_t character_id,
        const std::array<std::array<std::uint64_t, 2>, 60>& buffs) const;
    void craft_character_items(std::uint32_t character_id, std::uint64_t gold,
        const std::vector<std::pair<std::uint16_t, CharacterItem>>& updates) const;
    void save_character_items(std::uint32_t character_id, std::uint64_t gold,
        const std::vector<CharacterItemPlacement>& updates,
        const std::vector<std::uint16_t>& buffs_to_remove = {},
        const std::optional<std::pair<std::uint32_t, std::uint32_t>>& hp_mp =
            std::nullopt,
        const std::optional<std::pair<std::uint32_t, std::uint32_t>>& account_cash =
            std::nullopt,
        const std::optional<std::array<std::array<std::uint64_t, 2>, 60>>& buffs =
            std::nullopt,
        const std::optional<CharacterProgression>& progression = std::nullopt,
        const std::vector<std::pair<std::uint16_t, std::uint16_t>>& event_rewards = {},
        const std::vector<std::pair<std::uint16_t, std::uint16_t>>& event_claims = {},
        const std::optional<std::uint64_t>& last_diary_event = std::nullopt,
        const std::vector<CharacterTitle>& titles_to_add = {},
        const std::optional<std::uint32_t>& account_storage_owner = std::nullopt,
        const std::optional<std::uint32_t>& honor = std::nullopt) const;
    void set_account_active(std::uint32_t account_id, bool active) const;
    [[nodiscard]] std::uint64_t count_characters(std::uint32_t account_id) const;
    [[nodiscard]] std::optional<std::uint32_t> create_character(
        std::uint32_t account_id, const NewCharacterData& character) const;
    void save_account_token(const std::string& username, const std::string& token,
                            std::int64_t creation_time, std::uint64_t premium_time) const;
    void clear_expired_ban(const std::string& username) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace aika::database
