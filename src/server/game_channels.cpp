#include "aika/server/game_channels.hpp"

#include "aika/database/mysql_connection.hpp"
#include "aika/protocol/crypto.hpp"
#include "aika/protocol/frame_decoder.hpp"
#include "aika/protocol/packet_header.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <functional>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <limits>
#include <iomanip>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aika::server {
namespace {

constexpr std::uint16_t login_opcode = 0x0685U;
constexpr std::uint16_t character_list_opcode = 0x0901U;
constexpr std::uint16_t numeric_token_opcode = 0x0f02U;
constexpr std::uint16_t enter_world_opcode = 0x0f0bU;
constexpr std::uint16_t world_character_opcode = 0x0925U;
constexpr std::uint16_t create_mob_opcode = 0x0349U;
constexpr std::uint16_t send_skills_opcode = 0x0106U;
constexpr std::uint16_t current_hp_mp_opcode = 0x0103U;
constexpr std::uint16_t refresh_level_opcode = 0x0108U;
constexpr std::uint16_t refresh_points_opcode = 0x0109U;
constexpr std::uint16_t movement_opcode = 0x0301U;
constexpr std::uint16_t attack_target_opcode = 0x0302U;
constexpr std::uint16_t revive_player_opcode = 0x0303U;
constexpr std::uint16_t update_action_opcode = 0x0304U;
constexpr std::uint16_t rotation_opcode = 0x0305U;
constexpr std::uint16_t cancel_skill_launching_opcode = 0x0327U;
constexpr std::uint16_t open_npc_opcode = 0x030fU;
constexpr std::uint16_t buy_npc_item_opcode = 0x0313U;
constexpr std::uint16_t sell_npc_item_opcode = 0x0314U;
constexpr std::uint16_t repair_items_opcode = 0x0340U;
constexpr std::uint16_t remove_mob_opcode = 0x0101U;
constexpr std::uint16_t close_npc_option_opcode = 0x0348U;
constexpr std::uint16_t chat_opcode = 0x0f86U;
constexpr std::uint16_t ping_reply_opcode = 0xf93bU;
constexpr std::uint16_t server_time_request_opcode = 0x0202U;
constexpr std::uint16_t server_ping_request_opcode = 0xf93aU;
constexpr std::uint16_t move_item_opcode = 0x070fU;
constexpr std::uint16_t change_item_bar_opcode = 0x031eU;
constexpr std::uint16_t status_point_opcode = 0x0213U;
constexpr std::uint16_t learn_skill_opcode = 0x031cU;
constexpr std::uint16_t reset_skills_opcode = 0x032aU;
constexpr std::uint16_t remove_buff_opcode = 0x0329U;
constexpr std::uint16_t make_item_opcode = 0x032bU;
constexpr std::uint16_t delete_item_opcode = 0x032cU;
constexpr std::uint16_t group_item_opcode = 0x0332U;
constexpr std::uint16_t ungroup_item_opcode = 0x0333U;
constexpr std::uint16_t unseal_item_opcode = 0x0224U;
constexpr std::uint16_t use_item_opcode = 0x031dU;
constexpr std::uint16_t receive_event_item_opcode = 0x0359U;
constexpr std::uint16_t use_buff_item_opcode = 0x021bU;
constexpr std::uint16_t create_character_opcode = 0x3e04U;
constexpr std::uint16_t request_delete_character_opcode = 0x0603U;
constexpr std::uint16_t delete_character_opcode = 0x3e01U;
constexpr std::uint16_t refresh_item_opcode = 0x0f0eU;
constexpr std::size_t character_wire_size = 4216U;
std::atomic_uint32_t next_client_id{1U};

[[nodiscard]] bool is_inventory_slot_unlocked(
        const std::array<database::CharacterItem, 64>& inventory,
        const std::uint16_t slot) noexcept {
    if (slot >= 60U) return false;
    // The first page is the character's built-in backpack. Each later page is
    // unlocked by its matching bag slot: 61 -> 15..29, 62 -> 30..44, 63 -> 45..59.
    return slot < 15U || inventory[60U + slot / 15U].item_id != 0U;
}

[[nodiscard]] std::size_t empty_unlocked_inventory_slots(
        const std::array<database::CharacterItem, 64>& inventory) noexcept {
    std::size_t count{};
    for (std::uint16_t slot = 0U; slot < 60U; ++slot)
        if (is_inventory_slot_unlocked(inventory, slot) &&
            inventory[slot].item_id == 0U) ++count;
    return count;
}

[[nodiscard]] std::optional<std::uint16_t> first_empty_inventory_slot(
        const std::array<database::CharacterItem, 64>& inventory) noexcept {
    for (std::uint16_t slot = 0U; slot < 60U; ++slot)
        if (is_inventory_slot_unlocked(inventory, slot) &&
            inventory[slot].item_id == 0U) return slot;
    return std::nullopt;
}

[[nodiscard]] std::uint16_t read_u16(const std::span<const std::byte> data,
        const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(data[offset]) |
        (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(data[offset + 1U])) << 8U));
}

[[nodiscard]] std::uint32_t read_u32(const std::span<const std::byte> data,
        const std::size_t offset) noexcept {
    return static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[offset])) |
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[offset + 1U])) << 8U) |
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[offset + 2U])) << 16U) |
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[offset + 3U])) << 24U);
}

void write_u16(const std::uint16_t value, const std::span<std::byte> data,
        const std::size_t offset) noexcept {
    data[offset] = static_cast<std::byte>(value & 0xffU);
    data[offset + 1U] = static_cast<std::byte>((value >> 8U) & 0xffU);
}

void write_u32(const std::uint32_t value, const std::span<std::byte> data,
        const std::size_t offset) noexcept {
    for (std::size_t i = 0U; i < 4U; ++i)
        data[offset + i] = static_cast<std::byte>((value >> (8U * i)) & 0xffU);
}

void write_f32(const float value, const std::span<std::byte> data,
        const std::size_t offset) noexcept {
    const auto bits = std::bit_cast<std::uint32_t>(value);
    write_u32(bits, data, offset);
}

void write_u64(const std::uint64_t value, const std::span<std::byte> data,
        const std::size_t offset) noexcept {
    for (std::size_t i = 0U; i < 8U; ++i)
        data[offset + i] = static_cast<std::byte>((value >> (8U * i)) & 0xffU);
}

[[nodiscard]] std::string fixed_string(const std::span<const std::byte> data,
        const std::size_t offset, const std::size_t size) {
    if (offset > data.size() || size > data.size() - offset) return {};
    std::string value;
    for (std::size_t i = 0U; i < size; ++i) {
        const auto c = std::to_integer<unsigned char>(data[offset + i]);
        if (c == 0U) break;
        value.push_back(static_cast<char>(c));
    }
    while (!value.empty() && value.back() == ' ') value.pop_back();
    std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char c) {
        return static_cast<char>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
    });
    return value;
}

[[nodiscard]] std::string peer_ipv4_address(const SOCKET socket) {
    sockaddr_in peer{};
    int peer_size = static_cast<int>(sizeof(peer));
    if (getpeername(socket, reinterpret_cast<sockaddr*>(&peer), &peer_size) == SOCKET_ERROR ||
        peer.sin_family != AF_INET) return {};
    std::array<char, INET_ADDRSTRLEN> address{};
    if (InetNtopA(AF_INET, &peer.sin_addr, address.data(),
            static_cast<DWORD>(address.size())) == nullptr) return {};
    return address.data();
}

[[nodiscard]] std::string fixed_bytes(const std::span<const std::byte> data,
        const std::size_t offset, const std::size_t size) {
    if (offset > data.size() || size > data.size() - offset) return {};
    std::string value;
    for (std::size_t i = 0U; i < size; ++i) {
        const auto c = std::to_integer<unsigned char>(data[offset + i]);
        if (c == 0U) break;
        value.push_back(static_cast<char>(c));
    }
    while (!value.empty() && value.back() == ' ') value.pop_back();
    return value;
}

[[nodiscard]] std::optional<std::time_t> parse_local_datetime(
        const std::string_view value) {
    for (const auto* format : {"%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S"}) {
        std::tm parsed{};
        std::istringstream input{std::string{value}};
        input >> std::get_time(&parsed, format);
        if (input.fail()) continue;
        parsed.tm_isdst = -1;
        const auto timestamp = std::mktime(&parsed);
        if (timestamp >= 0) return timestamp;
    }
    return std::nullopt;
}

[[nodiscard]] std::string format_local_datetime(const std::time_t timestamp) {
    std::tm local{};
    if (localtime_s(&local, &timestamp) != 0) return {};
    std::ostringstream output;
    output << std::put_time(&local, "%Y-%m-%d %H:%M:%S");
    return output.str();
}

[[nodiscard]] std::string local_datetime_after_days(const std::uint16_t days) {
    const auto now = std::time(nullptr);
    std::tm local{};
    if (localtime_s(&local, &now) != 0) return {};
    local.tm_mday += days;
    local.tm_isdst = -1;
    const auto target = std::mktime(&local);
    return target < 0 ? std::string{} : format_local_datetime(target);
}

[[nodiscard]] std::uint8_t random_transport_key() {
    std::uint8_t value{};
    if (BCryptGenRandom(nullptr, &value, sizeof(value), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw std::runtime_error{"Windows cryptographic random generation failed"};
    return static_cast<std::uint8_t>(value % 255U);
}

[[nodiscard]] std::uint32_t next_local_midnight_unix(const int hour) noexcept {
    const auto current = std::time(nullptr);
    std::tm local{};
    if (localtime_s(&local, &current) != 0) return 0U;
    local.tm_mday += 1;
    local.tm_hour = hour;
    local.tm_min = 0;
    local.tm_sec = 0;
    const auto target = std::mktime(&local);
    return target < 0 ? 0U : static_cast<std::uint32_t>(target);
}

[[nodiscard]] std::string local_datetime_string() {
    const auto now = std::chrono::system_clock::now();
    const auto seconds = std::chrono::system_clock::to_time_t(now);
    std::tm local{};
    if (localtime_s(&local, &seconds) != 0) return {};
    std::ostringstream value;
    value << std::put_time(&local, "%d/%m/%Y %H:%M:%S");
    return value.str();
}

constexpr std::size_t effect_capacity = 512U;

[[nodiscard]] std::array<std::int64_t, effect_capacity> calculate_passive_skill_effects(
        const database::CharacterRecord& character,
        const data::GameTables& tables) noexcept {
    constexpr std::size_t ef_damage1 = 2U;
    constexpr std::size_t ef_damage2 = 3U;
    constexpr std::size_t ef_resistance6 = 20U;
    constexpr std::size_t ef_resistance7 = 21U;
    constexpr std::size_t ef_cast_rate = 28U;
    constexpr std::size_t ef_critical_power = 31U;
    constexpr std::size_t ef_runspeed = 46U;
    constexpr std::size_t ef_critical = 50U;
    constexpr std::size_t ef_parry = 51U;
    constexpr std::size_t ef_hit = 53U;
    constexpr std::size_t ef_regen_hp = 64U;
    constexpr std::size_t ef_regen_mp = 65U;
    constexpr std::size_t ef_skill_damage = 66U;
    constexpr std::size_t ef_state_resistance = 80U;
    constexpr std::size_t ef_hp = 13U;
    constexpr std::size_t ef_mp = 14U;
    constexpr std::size_t ef_cooltime = 48U;
    constexpr std::size_t ef_skill_atime6 = 122U;
    constexpr std::size_t ef_mp_cure = 157U;
    constexpr std::size_t ef_pran_require_mp = 194U;
    constexpr std::size_t ef_skill_damage6 = 214U;
    constexpr std::size_t ef_guard = 237U;
    constexpr std::size_t ef_guard_rate = 238U;
    constexpr std::size_t ef_im_runspeed = 242U;
    constexpr std::size_t ef_im_skill_immovable = 243U;
    constexpr std::size_t ef_im_silence1 = 246U;
    constexpr std::size_t ef_im_fear = 247U;
    constexpr std::size_t ef_im_skill_shock = 249U;
    constexpr std::size_t ef_manaburn = 305U;
    constexpr std::size_t ef_deceive_atk = 358U;
    constexpr std::size_t ef_require_mp = 112U;
    constexpr std::size_t ef_hp_atk_res = 395U;

    std::array<std::int64_t, effect_capacity> effects{};
    const auto add = [&effects](const std::size_t effect, const std::int64_t value) {
        if (effect < effects.size()) effects[effect] += value;
    };

    // Delphi SearchSkillsPassive scans only Skills.Others (the last 40 of 46
    // persisted skill placements) and activates passive, non-elemental skills.
    for (std::size_t slot = 6U; slot < character.skills.size(); ++slot) {
        const auto [skill_id, level] = character.skills[slot];
        if (skill_id == 0U || level == 0U || skill_id >= tables.skill_definitions.size())
            continue;
        const auto& skill = tables.skill_definitions[skill_id];
        if ((skill.aggressive != 1U && skill.aggressive != 2U) || skill.attribute != 0)
            continue;
        const auto rank = static_cast<std::int64_t>(level);
        switch (skill.index) {
        case 9U: add(ef_damage1, rank * 2); add(ef_hit, rank * 4); break;
        case 10U: add(ef_hp, rank * 145); add(ef_regen_hp, rank * 100); break;
        case 146U: add(ef_cooltime, rank * 2); break;
        case 23U: add(270U, 30 + rank * 2); add(ef_critical, rank); break;
        case 33U: add(ef_hp_atk_res, rank); break;
        case 34U: add(ef_skill_damage6, rank * 120); add(ef_mp_cure, 10 + rank * 2); break;
        case 149U: add(ef_guard_rate, 10 + rank * 2); add(ef_guard, 5 + rank); break;
        case 47U: add(ef_damage1, 8 + rank * 4); add(ef_critical, rank); break;
        case 57U: add(ef_hit, rank * 2); break;
        case 58U: add(ef_critical_power, 5 + rank * 5); break;
        case 152U: add(ef_runspeed, 1 + rank); add(ef_skill_damage, 50 + rank * 50); break;
        case 71U: add(ef_resistance6, rank * 3); add(ef_resistance7, rank * 3); break;
        case 81U: add(ef_critical, rank); add(ef_critical_power, rank * 3); break;
        case 82U: add(ef_parry, 2 + rank); break;
        case 155U: add(ef_im_runspeed, rank * 5); add(ef_im_skill_immovable, rank * 3); break;
        case 95U: add(ef_state_resistance, 8 + rank * 2); add(ef_deceive_atk, rank); break;
        case 105U: add(ef_damage2, rank * 5); add(ef_pran_require_mp, rank * 3); break;
        case 106U: add(ef_mp, rank * 80); add(ef_regen_mp, rank * 5); break;
        case 158U: add(ef_im_silence1, rank * 5); add(ef_im_fear, rank * 3); break;
        case 119U: add(ef_cast_rate, rank * 4); add(ef_manaburn, 4 + rank); break;
        case 129U: add(ef_skill_damage6, rank * 120); add(ef_mp_cure, 8 + rank * 2); break;
        case 130U: add(ef_skill_atime6, rank * 2); add(ef_require_mp, 10 + rank); break;
        case 161U: add(ef_im_skill_immovable, rank * 5); add(ef_im_skill_shock, rank * 3); break;
        case 143U: add(ef_skill_damage6, 17 + rank * 3); break;
        default: break;
        }
    }
    return effects;
}

[[nodiscard]] bool is_expired_equipment_marker(
        const database::CharacterItem& item, const data::GameTables& tables) noexcept {
    if (item.item_id == 0U || item.item_id >= tables.item_definitions.size()) return false;
    const auto& definition = tables.item_definitions[item.item_id];
    const bool expired_pran_clothing = item.min == 0xffU && item.max == 0xffU &&
        definition.class_id >= 100U && definition.class_id <= 104U;
    const bool expired_mount = item.time == 0xffffU && definition.item_type == 9U;
    return expired_pran_clothing || expired_mount;
}

[[nodiscard]] std::pair<std::uint32_t, std::uint32_t> estimate_max_hp_mp(
        const database::CharacterRecord& character, const data::GameTables& tables) noexcept {
    constexpr std::array<int, 6U> hp_per_level{150, 140, 115, 120, 110, 130};
    constexpr std::array<int, 6U> mp_per_level{110, 130, 145, 150, 330, 135};
    std::size_t mob_class = 0U;
    if (character.class_info >= 11U && character.class_info <= 19U) mob_class = 1U;
    else if (character.class_info >= 21U && character.class_info <= 29U) mob_class = 2U;
    else if (character.class_info >= 31U && character.class_info <= 39U) mob_class = 3U;
    else if (character.class_info >= 41U && character.class_info <= 49U) mob_class = 4U;
    else if (character.class_info >= 51U && character.class_info <= 59U) mob_class = 5U;

    const auto level = std::max<std::uint16_t>(character.level, 1U);
    std::uint64_t hp = static_cast<std::uint64_t>(std::nearbyint(
        static_cast<double>(hp_per_level[mob_class]) * 0.3)) * level;
    std::uint64_t mp = static_cast<std::uint64_t>(std::nearbyint(
        static_cast<double>(mp_per_level[mob_class]) * 0.3)) * level;
    hp += static_cast<std::uint64_t>(character.attributes[3U]) * 27U;
    mp += static_cast<std::uint64_t>(character.attributes[4U]) * 27U;
    const auto passive_effects = calculate_passive_skill_effects(character, tables);
    hp += static_cast<std::uint64_t>(std::max<std::int64_t>(passive_effects[13U], 0));
    mp += static_cast<std::uint64_t>(std::max<std::int64_t>(passive_effects[14U], 0));
    for (std::size_t slot = 2U; slot <= 7U; ++slot) {
        if (slot == 6U) continue;
        if (is_expired_equipment_marker(character.equipment[slot], tables)) continue;
        const auto item_id = character.equipment[slot].item_id;
        if (item_id < tables.item_definitions.size()) {
            hp += tables.item_definitions[item_id].hp;
            mp += tables.item_definitions[item_id].mp;
        }
    }
    const auto bounded = [](const std::uint64_t value, const std::uint32_t current) {
        return static_cast<std::uint32_t>(std::min<std::uint64_t>(
            std::max<std::uint64_t>(value, current), 0xffffffffULL));
    };
    return {bounded(hp, character.current_hp), bounded(mp, character.current_mp)};
}

[[nodiscard]] bool character_has_effect(
        const database::CharacterRecord& character,
        const data::GameTables& tables, const std::size_t target_effect) noexcept {
    for (const auto& equipped : character.equipment) {
        if (equipped.item_id == 0U ||
            equipped.item_id >= tables.item_definitions.size() ||
            is_expired_equipment_marker(equipped, tables)) continue;
        const auto& definition = tables.item_definitions[equipped.item_id];
        for (std::size_t i = 0U; i < equipped.effect_index.size(); ++i)
            if (equipped.effect_index[i] == target_effect &&
                equipped.effect_value[i] != 0U) return true;
        for (std::size_t i = 0U; i < definition.effects.size(); ++i)
            if (definition.effects[i] == target_effect &&
                definition.effect_values[i] > 0) return true;
    }
    const auto now = static_cast<std::uint64_t>(std::time(nullptr));
    for (const auto& buff : character.buffs) {
        const auto skill_id = static_cast<std::size_t>(buff[0]);
        if (skill_id == 0U || skill_id >= tables.skill_definitions.size()) continue;
        const auto& definition = tables.skill_definitions[skill_id];
        if (buff[1] <= now && definition.duration <= now - buff[1]) continue;
        for (std::size_t i = 0U; i < definition.effects.size(); ++i)
            if (definition.effects[i] == static_cast<std::int32_t>(target_effect) &&
                definition.effect_values[i] > 0) return true;
    }
    const auto passive = calculate_passive_skill_effects(character, tables);
    return target_effect < passive.size() && passive[target_effect] > 0;
}

struct CharacterCombatStatus final {
    std::uint16_t physical_attack{};
    std::uint16_t physical_defense{};
    std::uint16_t magical_attack{};
    std::uint16_t magical_defense{};
    std::uint16_t move_speed{};
    std::uint16_t critical{};
    std::uint8_t evade{};
    std::uint8_t hit{};
    std::uint16_t double_attack{};
    std::uint16_t state_resistance{};
};

[[nodiscard]] std::uint16_t add_word(const std::uint16_t value,
        const std::int64_t amount) noexcept {
    const auto result = static_cast<std::int64_t>(value) + amount;
    return static_cast<std::uint16_t>(std::clamp<std::int64_t>(result, 0, 65535));
}

[[nodiscard]] std::uint16_t add_critical(const std::uint16_t value,
        const std::int64_t amount) noexcept {
    const auto result = static_cast<std::int64_t>(value) + amount;
    return static_cast<std::uint16_t>(std::clamp<std::int64_t>(result, 0, 255));
}

[[nodiscard]] std::uint8_t add_byte(const std::uint8_t value,
        const std::int64_t amount) noexcept {
    const auto result = static_cast<std::int64_t>(value) + amount;
    return static_cast<std::uint8_t>(std::clamp<std::int64_t>(result, 0, 255));
}

[[nodiscard]] int item_equip_slot(const data::ItemDefinition& item) noexcept {
    if (item.item_type == 50U || item.item_type == 52U) return 15;
    if (item.item_type > 0U && item.item_type < 16U) return item.item_type;
    if (item.item_type > 1000U && item.item_type < 1011U) return 6;
    return 0;
}

[[nodiscard]] unsigned item_class_bucket(const std::uint16_t class_info) noexcept {
    if (class_info >= 1U && class_info <= 9U) return 0U;
    if (class_info >= 11U && class_info <= 19U) return 1U;
    if (class_info >= 21U && class_info <= 29U) return 2U;
    if (class_info >= 31U && class_info <= 39U) return 3U;
    if (class_info >= 41U && class_info <= 49U) return 4U;
    if (class_info >= 51U && class_info <= 59U) return 5U;
    return 0U;
}

[[nodiscard]] std::size_t item_reinforcement_index(
        const data::ItemDefinition& item) noexcept {
    const auto use_effect = static_cast<std::size_t>(item.use_effect);
    std::size_t base = 0U;
    if (use_effect <= 35U) base = 0U;
    else if (use_effect <= 70U) base = 960U - 35U;
    else if (use_effect <= 105U) base = 1920U - 70U;
    else return (std::numeric_limits<std::size_t>::max)();

    const auto slot = item_equip_slot(item);
    if (slot == 6) {
        constexpr std::array<std::size_t, 6U> weapon_offsets{
            35U, 0U, 105U, 70U, 175U, 140U};
        return base + weapon_offsets[item_class_bucket(item.class_id)] + use_effect;
    }
    switch (slot) {
    case 2: base += 210U + item_class_bucket(item.class_id) * 30U; break;
    case 3: base += 390U + item_class_bucket(item.class_id) * 30U; break;
    case 4: base += 570U + item_class_bucket(item.class_id) * 30U; break;
    case 5: base += 750U + item_class_bucket(item.class_id) * 30U; break;
    case 7: base += 930U; break;
    default: return (std::numeric_limits<std::size_t>::max)();
    }
    return base + use_effect;
}

[[nodiscard]] CharacterCombatStatus calculate_combat_status(
        const database::CharacterRecord& character,
        const data::GameTables& tables) noexcept {
    // Effect identifiers here match the active Delphi GlobalDefs constants.
    constexpr std::size_t ef_damage1 = 2U;
    constexpr std::size_t ef_damage2 = 3U;
    constexpr std::size_t ef_resistance1 = 8U;
    constexpr std::size_t ef_resistance2 = 9U;
    constexpr std::size_t ef_str = 15U;
    constexpr std::size_t ef_dex = 16U;
    constexpr std::size_t ef_int = 17U;
    constexpr std::size_t ef_con = 18U;
    constexpr std::size_t ef_spi = 19U;
    constexpr std::size_t ef_runspeed = 46U;
    constexpr std::size_t ef_double = 49U;
    constexpr std::size_t ef_critical = 50U;
    constexpr std::size_t ef_parry = 51U;
    constexpr std::size_t ef_hit = 53U;
    constexpr std::size_t ef_per_damage1 = 54U;
    constexpr std::size_t ef_per_damage2 = 55U;
    constexpr std::size_t ef_per_resistance1 = 59U;
    constexpr std::size_t ef_per_resistance2 = 60U;
    constexpr std::size_t ef_state_resistance = 80U;
    constexpr std::size_t ef_unarmor = 159U;
    constexpr std::size_t ef_pran_damage1 = 182U;
    constexpr std::size_t ef_pran_damage2 = 183U;
    constexpr std::size_t ef_pran_resistance1 = 186U;
    constexpr std::size_t ef_pran_resistance2 = 187U;
    constexpr std::size_t ef_pran_parry = 193U;
    constexpr std::size_t ef_decrease_per_damage1 = 319U;
    constexpr std::size_t ef_decrease_per_damage2 = 320U;

    std::array<std::int64_t, effect_capacity> effects{};
    const auto add_effect = [&effects](const std::uint32_t index,
            const std::int64_t value) {
        if (index < effects.size()) effects[index] += value;
    };
    for (const auto& equipped : character.equipment) {
        if (equipped.item_id == 0U || equipped.item_id >= tables.item_definitions.size())
            continue;
        if (is_expired_equipment_marker(equipped, tables)) continue;
        const auto& definition = tables.item_definitions[equipped.item_id];
        for (std::size_t i = 0U; i < equipped.effect_index.size(); ++i)
            if (equipped.effect_index[i] != 0U)
                add_effect(equipped.effect_index[i],
                    static_cast<std::int64_t>(equipped.effect_value[i]) * 2);
        for (std::size_t i = 0U; i < definition.effects.size(); ++i)
            if (definition.effects[i] != 0U)
                add_effect(definition.effects[i], definition.effect_values[i]);
    }

    const auto current_time = static_cast<std::uint64_t>(std::time(nullptr));
    for (const auto& buff : character.buffs) {
        const auto skill_id = static_cast<std::size_t>(buff[0]);
        if (skill_id == 0U || skill_id >= tables.skill_definitions.size()) continue;
        const auto& definition = tables.skill_definitions[skill_id];
        const auto created_at = buff[1];
        if (created_at > current_time ||
            definition.duration > current_time - created_at) {
            for (std::size_t i = 0U; i < definition.effects.size(); ++i)
                if (definition.effects[i] > 0)
                    add_effect(static_cast<std::uint32_t>(definition.effects[i]),
                        definition.effect_values[i]);
        }
    }
    for (const auto& title : character.titles) {
        if (title.index != character.active_title || title.level == 0U ||
            title.index >= tables.titles.size() ||
            title.level > tables.titles[title.index].levels.size()) continue;
        const auto& level = tables.titles[title.index].levels[title.level - 1U];
        for (std::size_t i = 0U; i < level.effects.size(); ++i)
            if (level.effects[i] != 0U)
                add_effect(level.effects[i], level.effect_values[i]);
        break;
    }
    const auto passive_effects = calculate_passive_skill_effects(character, tables);
    for (std::size_t i = 0U; i < effects.size(); ++i)
        effects[i] += passive_effects[i];
    const auto effect = [&effects](const std::size_t index) { return effects[index]; };
    std::array<std::uint16_t, 5U> attributes{};
    attributes[0] = add_critical(character.attributes[0], effect(ef_str));
    attributes[1] = add_critical(character.attributes[1], effect(ef_dex));
    attributes[2] = add_critical(character.attributes[2], effect(ef_int));
    attributes[3] = add_critical(character.attributes[3], effect(ef_con));
    attributes[4] = add_critical(character.attributes[4], effect(ef_spi));

    CharacterCombatStatus status{};
    status.move_speed = static_cast<std::uint16_t>(std::clamp<std::int64_t>(
        40 + effect(ef_runspeed), 15, 70));
    status.double_attack = add_critical(0U,
        static_cast<std::int64_t>(attributes[0] * 0.21) + effect(ef_double));
    status.critical = add_critical(0U,
        static_cast<std::int64_t>(attributes[1] * 0.13) + effect(ef_critical));
    status.hit = add_byte(0U,
        static_cast<std::int64_t>(attributes[1] * 0.1) + effect(ef_hit));
    status.evade = add_byte(0U,
        static_cast<std::int64_t>(attributes[1] * 0.021) +
        effect(ef_pran_parry) + effect(ef_parry));
    status.state_resistance = add_critical(0U,
        static_cast<std::int64_t>(std::nearbyint(attributes[4] * 0.1)) +
        effect(ef_state_resistance));

    std::int64_t physical_defense = 0;
    std::int64_t magical_defense = 0;
    for (const std::size_t slot : {2U, 3U, 4U, 5U, 7U}) {
        const auto& item = character.equipment[slot];
        if (item.item_id == 0U || item.item_id >= tables.item_definitions.size() ||
            item.min == 0U || is_expired_equipment_marker(item, tables)) continue;
        const auto& definition = tables.item_definitions[item.item_id];
        if (item.refine < 16U || item.time != 0U) {
            physical_defense += definition.physical_defense;
            magical_defense += definition.magical_defense;
        } else {
            const auto reinforcement = item_reinforcement_index(definition);
            const auto level = static_cast<std::size_t>(item.refine / 16U - 1U);
            if (reinforcement < tables.reinforcement_attributes.size() && level < 16U) {
                physical_defense += tables.reinforcement_attributes[reinforcement].physical[level];
                magical_defense += tables.reinforcement_attributes[reinforcement].magical[level];
            }
        }
    }
    physical_defense += (physical_defense / 100) * effect(ef_per_resistance1);
    magical_defense += (magical_defense / 100) * effect(ef_per_resistance2);
    physical_defense += effect(ef_resistance1) + effect(ef_pran_resistance1);
    magical_defense += effect(ef_resistance2) + effect(ef_pran_resistance2);
    if (effect(ef_unarmor) > 0) {
        physical_defense = 0;
        magical_defense = 0;
    }
    status.physical_defense = add_word(0U, physical_defense);
    status.magical_defense = add_word(0U, magical_defense);

    std::int64_t physical_attack = 0;
    std::int64_t magical_attack = 0;
    const auto& weapon = character.equipment[6U];
    if (weapon.item_id != 0U && weapon.item_id < tables.item_definitions.size() &&
        weapon.min != 0U && !is_expired_equipment_marker(weapon, tables)) {
        const auto& definition = tables.item_definitions[weapon.item_id];
        if (weapon.refine < 16U || weapon.time != 0U) {
            physical_attack = definition.physical_attack;
            magical_attack = definition.magical_attack;
        } else {
            const auto reinforcement = item_reinforcement_index(definition);
            const auto level = static_cast<std::size_t>(weapon.refine / 16U - 1U);
            if (reinforcement < tables.reinforcement_attributes.size() && level < 16U) {
                physical_attack = tables.reinforcement_attributes[reinforcement].physical[level];
                magical_attack = tables.reinforcement_attributes[reinforcement].magical[level];
            }
        }
    }
    physical_attack += static_cast<std::int64_t>(attributes[0] * 2.6) +
        static_cast<std::int64_t>(attributes[1] * 2.6) + effect(ef_pran_damage1);
    physical_attack += (physical_attack / 100) * effect(ef_per_damage1);
    physical_attack -= (physical_attack / 100) * effect(ef_decrease_per_damage1);
    physical_attack += effect(ef_damage1);
    magical_attack += static_cast<std::int64_t>(attributes[2] * 3.2) +
        effect(ef_pran_damage2);
    magical_attack += (magical_attack / 100) * effect(ef_per_damage2);
    magical_attack -= (magical_attack / 100) * effect(ef_decrease_per_damage2);
    magical_attack += effect(ef_damage2);
    status.physical_attack = add_word(0U, physical_attack);
    status.magical_attack = add_word(0U, magical_attack);
    return status;
}

[[nodiscard]] std::vector<std::byte> make_refresh_status_packet(
        const database::CharacterRecord& character, const data::GameTables& tables) {
    std::vector<std::byte> packet(44U);
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = 0x7535U;
    header.opcode = 0x010aU;
    const auto encoded = protocol::encode_header(header);
    std::copy(encoded.begin(), encoded.end(), packet.begin());
    const auto status = calculate_combat_status(character, tables);
    const auto bytes = std::span<std::byte>{packet};
    write_u16(status.physical_attack, bytes, 12U);
    write_u16(status.physical_defense, bytes, 14U);
    write_u16(status.magical_attack, bytes, 16U);
    write_u16(status.magical_defense, bytes, 18U);
    write_u16(status.move_speed, bytes, 26U);
    write_u16(status.critical, bytes, 36U);
    bytes[38U] = static_cast<std::byte>(status.evade);
    bytes[39U] = static_cast<std::byte>(status.hit);
    write_u16(status.double_attack, bytes, 40U);
    write_u16(status.state_resistance, bytes, 42U);
    return packet;
}

[[nodiscard]] bool send_all(const SOCKET socket, const std::span<const std::byte> bytes) {
    std::size_t sent_total = 0U;
    while (sent_total < bytes.size()) {
        const auto sent = send(socket,
            reinterpret_cast<const char*>(bytes.data() + sent_total),
            static_cast<int>(bytes.size() - sent_total), 0);
        if (sent <= 0) return false;
        sent_total += static_cast<std::size_t>(sent);
    }
    return true;
}

[[nodiscard]] bool send_encrypted(const SOCKET socket, std::vector<std::byte>& packet) {
    const auto encrypted = protocol::encrypt_frame(packet, random_transport_key(),
        static_cast<std::uint32_t>(GetTickCount()));
    return encrypted && send_all(socket, packet);
}

[[nodiscard]] std::array<std::byte, 16U> make_signal_packet(
        const std::uint16_t client_id, const std::uint16_t opcode,
        const std::uint32_t data) {
    std::array<std::byte, 16U> packet{};
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = client_id;
    header.opcode = opcode;
    const auto encoded = protocol::encode_header(header);
    std::copy(encoded.begin(), encoded.end(), packet.begin());
    write_u32(data, packet, 12U);
    return packet;
}

[[nodiscard]] std::array<std::byte, 12U> make_header_signal_packet(
        const std::uint16_t client_id, const std::uint16_t opcode) {
    std::array<std::byte, 12U> packet{};
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = client_id;
    header.opcode = opcode;
    const auto encoded = protocol::encode_header(header);
    std::copy(encoded.begin(), encoded.end(), packet.begin());
    return packet;
}

[[nodiscard]] std::array<std::byte, 336U> make_character_list(
        const database::AccountRecord& account,
        const std::vector<database::CharacterRecord>& characters,
        const std::uint16_t client_id) {
    std::array<std::byte, 336U> packet{};
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = client_id;
    header.opcode = character_list_opcode;
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), packet.begin());
    const auto bytes = std::span<std::byte>{packet};
    write_u32(account.id, bytes, 12U);

    for (const auto& character : characters) {
        if (character.slot >= 3U) continue;
        const auto base = 24U + static_cast<std::size_t>(character.slot) * 104U;
        const auto name_length = std::min<std::size_t>(character.name.size(), 16U);
        std::copy_n(reinterpret_cast<const std::byte*>(character.name.data()),
            name_length, packet.begin() + static_cast<std::ptrdiff_t>(base));
        write_u16(static_cast<std::uint16_t>(account.nation), bytes, base + 16U);
        write_u16(character.class_info, bytes, base + 18U);
        for (std::size_t i = 0U; i < character.sizes.size(); ++i)
            packet[base + 20U + i] = static_cast<std::byte>(character.sizes[i]);
        for (std::size_t i = 0U; i < character.equipment.size(); ++i) {
            const auto item_index = i < 2U
                ? character.equipment[i].item_id : character.equipment[i].app;
            write_u16(static_cast<std::uint16_t>(item_index), bytes, base + 24U + i * 2U);
        }
        packet[base + 47U] = static_cast<std::byte>(character.equipment[6].refine / 16U);
        for (std::size_t i = 0U; i < character.attributes.size(); ++i)
            write_u16(character.attributes[i], bytes, base + 52U + i * 2U);
        write_u16(static_cast<std::uint16_t>(character.level - 1U), bytes, base + 64U);
        write_u64(character.experience & 0xffffffffULL, bytes, base + 72U);
        write_u64(character.gold & 0xffffffffULL, bytes, base + 80U);
        if (character.deleted) {
            const auto delete_at = parse_local_datetime(character.delete_time);
            if (delete_at.has_value() && *delete_at > 0)
                write_u32(static_cast<std::uint32_t>(*delete_at), bytes, base + 92U);
        }
        packet[base + 96U] = static_cast<std::byte>(character.numeric_errors);
        packet[base + 97U] = static_cast<std::byte>(!character.numeric_token.empty());
        std::clog << "[game] character-list entry slot=" << character.slot
                  << " pin_registered="
                  << (character.numeric_token.empty() ? "no" : "yes")
                  << " pin_errors=" << static_cast<unsigned>(character.numeric_errors)
                  << std::endl;
    }
    return packet;
}

void write_item(const database::CharacterItem& item, const std::span<std::byte> bytes,
        const std::size_t offset) noexcept {
    write_u16(static_cast<std::uint16_t>(item.item_id), bytes, offset);
    write_u16(static_cast<std::uint16_t>(item.app), bytes, offset + 2U);
    write_u32(item.identific, bytes, offset + 4U);
    for (std::size_t i = 0U; i < 3U; ++i) {
        bytes[offset + 8U + i] = static_cast<std::byte>(item.effect_index[i]);
        bytes[offset + 11U + i] = static_cast<std::byte>(item.effect_value[i]);
    }
    bytes[offset + 14U] = static_cast<std::byte>(item.min);
    bytes[offset + 15U] = static_cast<std::byte>(item.max);
    write_u16(static_cast<std::uint16_t>(item.refine), bytes, offset + 16U);
    write_u16(static_cast<std::uint16_t>(item.time), bytes, offset + 18U);
}

[[nodiscard]] std::vector<std::byte> make_refresh_item_packet(
        const std::uint16_t slot_type, const std::uint16_t slot,
        const database::CharacterItem& item, const bool notice = false) {
    std::vector<std::byte> packet(36U);
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = 0x7535U;
    header.opcode = refresh_item_opcode;
    const auto encoded = protocol::encode_header(header);
    std::copy(encoded.begin(), encoded.end(), packet.begin());
    packet[12U] = static_cast<std::byte>(notice ? 1U : 0U);
    packet[13U] = static_cast<std::byte>(slot_type);
    write_u16(slot, packet, 14U);
    write_item(item, packet, 16U);
    return packet;
}

[[nodiscard]] std::vector<std::byte> make_storage_packet(
        const database::AccountRecord& account, const std::uint16_t client_id) {
    constexpr std::size_t item_wire_size = 20U;
    constexpr std::size_t items_offset = 24U;
    std::vector<std::byte> packet(items_offset +
        account.storage_items.size() * item_wire_size);
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = client_id;
    header.opcode = 0x0137U;
    const auto encoded = protocol::encode_header(header);
    std::copy(encoded.begin(), encoded.end(), packet.begin());
    write_u32(1U, packet, 12U);
    write_u64(account.storage_gold, packet, 16U);
    for (std::size_t slot = 0U; slot < account.storage_items.size(); ++slot) {
        const auto& item = account.storage_items[slot];
        const auto offset = items_offset + slot * item_wire_size;
        write_u16(static_cast<std::uint16_t>(item.item_id), packet, offset);
        write_u16(static_cast<std::uint16_t>(item.app), packet, offset + 2U);
        write_u32(item.identific, packet, offset + 4U);
        for (std::size_t effect = 0U; effect < item.effect_index.size(); ++effect) {
            packet[offset + 8U + effect] = static_cast<std::byte>(item.effect_index[effect]);
            packet[offset + 11U + effect] = static_cast<std::byte>(item.effect_value[effect]);
        }
        packet[offset + 14U] = static_cast<std::byte>(item.min);
        packet[offset + 15U] = static_cast<std::byte>(item.max);
        write_u16(static_cast<std::uint16_t>(item.refine), packet, offset + 16U);
        write_u16(static_cast<std::uint16_t>(item.time), packet, offset + 18U);
    }
    return packet;
}

[[nodiscard]] std::array<std::byte, 24U> make_item_bar_packet(
        const std::uint32_t destination_slot, const std::uint32_t source_type,
        const std::uint32_t source_index) {
    std::array<std::byte, 24U> packet{};
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = 0x7535U;
    header.opcode = change_item_bar_opcode;
    const auto encoded = protocol::encode_header(header);
    std::copy(encoded.begin(), encoded.end(), packet.begin());
    write_u32(destination_slot, packet, 12U);
    write_u32(source_type, packet, 16U);
    write_u32(source_index, packet, 20U);
    return packet;
}

[[nodiscard]] std::vector<std::byte> make_world_character_packet(
        const database::AccountRecord& account,
        const database::CharacterRecord& character,
        const std::uint16_t client_id, const data::GameTables& tables) {
    std::vector<std::byte> packet(16U + character_wire_size);
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = 0x7535U;
    header.opcode = world_character_opcode;
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), packet.begin());
    const auto bytes = std::span<std::byte>{packet};
    write_u32(account.id, bytes, 12U);
    constexpr std::size_t base = 16U;

    // TCharacter is a packed 4,216-byte Delphi record. Fields with no database
    // source remain zero, matching the zero-initialized destination packet.
    write_u32(client_id, bytes, base);
    write_u32(character.id, bytes, base + 8U);
    std::copy_n(reinterpret_cast<const std::byte*>(character.name.data()),
        std::min<std::size_t>(character.name.size(), 16U),
        packet.begin() + static_cast<std::ptrdiff_t>(base + 12U));
    packet[base + 28U] = static_cast<std::byte>(account.nation);
    packet[base + 29U] = static_cast<std::byte>(character.class_info);

    constexpr std::size_t status = base + 32U;
    for (std::size_t i = 0U; i < character.attributes.size(); ++i)
        write_u16(character.attributes[i], bytes, status + i * 2U);
    for (std::size_t i = 0U; i < character.sizes.size(); ++i)
        packet[status + 12U + i] = static_cast<std::byte>(character.sizes[i]);
    const auto [max_hp, max_mp] = estimate_max_hp_mp(character, tables);
    write_u32(max_hp, bytes, status + 16U);
    write_u32((std::min)(character.current_hp, max_hp), bytes, status + 20U);
    write_u32(max_mp, bytes, status + 24U);
    write_u32((std::min)(character.current_mp, max_mp), bytes, status + 28U);
    write_u32(next_local_midnight_unix(6), bytes, status + 32U);
    write_u32(character.honor, bytes, status + 36U);
    write_u32(character.kill_points, bytes, status + 40U);
    write_u32(character.infamy, bytes, status + 44U);
    write_u16(character.skill_points, bytes, status + 50U);

    write_u64(character.experience, bytes, base + 176U);
    write_u16(static_cast<std::uint16_t>(character.level - 1U), bytes, base + 184U);
    write_u16(static_cast<std::uint16_t>(character.guild_id), bytes, base + 186U);
    for (std::size_t i = 0U; i < 20U; ++i) {
        write_u16(static_cast<std::uint16_t>(character.buffs[i][0]), bytes,
            base + 220U + i * 2U);
        write_u32(static_cast<std::uint32_t>(character.buffs[i][1]), bytes,
            base + 260U + i * 4U);
    }
    for (std::size_t i = 0U; i < character.equipment.size(); ++i)
        write_item(character.equipment[i], bytes, base + 340U + i * 20U);
    for (std::size_t i = 0U; i < character.inventory.size(); ++i)
        write_item(character.inventory[i], bytes, base + 664U + i * 20U);
    write_u64(character.gold, bytes, base + 1944U);
    for (std::size_t i = 0U; i < character.quests.size() && i < 16U; ++i)
        write_u16(static_cast<std::uint16_t>(character.quests[i].quest_id), bytes,
            base + 2144U + i * 12U);
    write_u32(character.creation_time, bytes, base + 2684U);
    std::copy_n(reinterpret_cast<const std::byte*>(character.numeric_token.data()),
        std::min<std::size_t>(character.numeric_token.size(), 4U),
        packet.begin() + static_cast<std::ptrdiff_t>(base + 3124U));
    for (std::size_t i = 0U; i < 6U; ++i)
        if (character.skills[i][1] != 0U)
            write_u16(2U, bytes, base + 3340U + i * 2U);
    for (std::size_t i = 0U; i < 40U; ++i) {
        const auto skill_id = character.skills[i + 6U][0];
        const auto skill_level = character.skills[i + 6U][1];
        if (skill_level == 0U) continue;
        const auto skill_index = static_cast<std::size_t>(skill_id) + skill_level - 1U;
        if (skill_index >= tables.skill_definitions.size()) continue;
        const auto exponent = tables.skill_definitions[skill_index].level + 1U;
        if (exponent >= 32U) continue;
        std::uint32_t encoded_level = (1U << exponent) - 2U;
        if (i > 0U && character.skills[i + 5U][1] == 16U) ++encoded_level;
        const auto skill_offset = base + 3340U + (i + 6U) * 2U;
        if (encoded_level <= 0xffffU)
            write_u16(static_cast<std::uint16_t>(encoded_level), bytes, skill_offset);
        else
            write_u32(encoded_level, bytes, skill_offset);
    }
    for (std::size_t i = 0U; i < character.item_bar.size() && i < 24U; ++i)
        write_u32(character.item_bar[i], bytes, base + 3460U + i * 4U);
    write_u16(character.active_title, bytes, base + 3688U);
    for (const auto& title : character.titles) {
        if (title.index == 0U || title.level == 0U || title.index >= tables.titles.size())
            continue;
        const auto category = static_cast<std::size_t>(title.index / 8U);
        const auto slot = static_cast<std::size_t>(title.index % 8U);
        if (category < 12U) {
            std::uint32_t contribution = 0U;
            for (std::uint32_t level = 1U; level <= title.level; ++level) {
                const auto shift = static_cast<unsigned>(slot * 4U + level - 1U);
                if (shift < 32U) contribution += (1U << shift);
            }
            const auto title_level_value = base + 3560U + category * 4U;
            write_u32(read_u32(bytes, title_level_value) + contribution, bytes,
                title_level_value);
        }
        const auto level = static_cast<std::size_t>(title.level - 1U);
        if (level >= tables.titles[title.index].levels.size()) continue;
        const auto& title_definition = tables.titles[title.index].levels[level];
        const auto title_progress_index = title_definition.index;
        switch (title_definition.type) {
        case 8U:
            if (title_progress_index >= 1U && title_progress_index <= 48U)
                write_u16(title.progress, bytes,
                    base + 3694U + (title_progress_index - 1U) * 2U);
            break;
        case 9U: write_u16(title.progress, bytes, base + 3792U); break;
        case 4U: write_u16(title.progress, bytes, base + 3794U); break;
        case 10U: write_u16(title.progress, bytes, base + 3796U); break;
        case 7U: write_u16(title.progress, bytes, base + 3798U); break;
        case 11U: write_u16(title.progress, bytes, base + 3800U); break;
        case 12U: write_u16(title.progress, bytes, base + 3802U); break;
        case 13U: write_u16(title.progress, bytes, base + 3804U); break;
        case 15U: write_u16(title.progress, bytes, base + 3806U); break;
        case 16U:
            if (title_progress_index >= 1U && title_progress_index <= 22U)
                write_u16(title.progress, bytes,
                    base + 3810U + (title_progress_index - 1U) * 2U);
            break;
        case 23U: write_u16(title.progress, bytes, base + 3854U); break;
        default: break;
        }
    }
    write_u32(next_local_midnight_unix(0), bytes, base + 4096U);
    write_u32(static_cast<std::uint32_t>(std::time(nullptr)), bytes, base + 4164U);
    return packet;
}

[[nodiscard]] std::vector<std::byte> make_create_mob_packet(
        const database::AccountRecord& account,
        const database::CharacterRecord& character,
        const std::uint16_t client_id, const data::GameTables& tables) {
    constexpr std::size_t packet_size = 508U;
    std::vector<std::byte> packet(packet_size);
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = client_id;
    header.opcode = create_mob_opcode;
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), packet.begin());
    const auto bytes = std::span<std::byte>{packet};
    std::copy_n(reinterpret_cast<const std::byte*>(character.name.data()),
        std::min<std::size_t>(character.name.size(), 16U), packet.begin() + 12);
    for (std::size_t slot = 0U; slot < 8U; ++slot) {
        const auto& item = character.equipment[slot];
        const auto displayed = slot >= 2U && item.app != 0U ? item.app : item.item_id;
        write_u16(static_cast<std::uint16_t>(displayed), bytes, 28U + slot * 2U);
    }
    packet[51U] = static_cast<std::byte>(character.equipment[6U].refine / 16U);
    write_f32(character.position_x, bytes, 56U);
    write_f32(character.position_y, bytes, 60U);
    write_u32(character.rotation, bytes, 64U);
    const auto [max_hp, max_mp] = estimate_max_hp_mp(character, tables);
    write_u32(max_hp, bytes, 68U);
    write_u32(max_mp, bytes, 72U);
    write_u32((std::min)(character.current_hp, max_hp), bytes, 76U);
    write_u32((std::min)(character.current_mp, max_mp), bytes, 80U);
    packet[84U] = std::byte{0x0aU};
    const auto configured_speed = character.move_speed;
    const auto movement_speed = configured_speed == 0U
        ? calculate_combat_status(character, tables).move_speed : configured_speed;
    packet[85U] = static_cast<std::byte>((std::min)(movement_speed, 255U));
    packet[86U] = std::byte{0U}; // SPAWN_NORMAL
    for (std::size_t i = 0U; i < character.sizes.size(); ++i)
        packet[87U + i] = static_cast<std::byte>(character.sizes[i]);
    // TSendCreateMobPacket.Effects[1] is at byte 492 (12-byte header included).
    // Byte 92 is EffectType and remains zero for player spawns in the Delphi server.
    write_u16(0x001dU, bytes, 492U);
    const auto guild_nation = static_cast<std::uint16_t>(
        ((account.nation & 0x0fU) << 12U) | (character.guild_id & 0x0fffU));
    write_u16(guild_nation, bytes, 488U);
    write_u16(character.active_title, bytes, 504U);
    for (const auto& title : character.titles) {
        if (title.index == character.active_title && title.level != 0U) {
            packet[505U] = static_cast<std::byte>(title.level - 1U);
            break;
        }
    }
    return packet;
}

[[nodiscard]] std::vector<std::byte> make_world_mob_packet(
        const data::MobSpawn& spawn, const data::MobTemplate& mob_template,
        const std::uint32_t current_hp, const bool nation_selected = true) {
    constexpr std::size_t packet_size = 84U;
    std::vector<std::byte> packet(packet_size);
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet_size);
    header.client_index = static_cast<std::uint16_t>(spawn.client_id);
    header.opcode = 0x035eU;
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), packet.begin());
    if (!mob_template.attributes.has_value()) return {};

    const auto& attributes = *mob_template.attributes;
    const auto bytes = std::span<std::byte>{packet};
    write_u16(attributes.weapon_id, bytes, 12U);
    write_u16(attributes.shield_id, bytes, 14U);
    write_u16(attributes.armor_id, bytes, 24U);
    write_f32(spawn.initial_x, bytes, 28U);
    write_f32(spawn.initial_y, bytes, 32U);
    write_u32(attributes.rotation, bytes, 36U);
    write_u32(current_hp, bytes, 40U);
    write_u32(attributes.initial_hp, bytes, 44U);
    write_u32(attributes.initial_hp, bytes, 48U);
    write_u32(current_hp, bytes, 52U);
    write_u16(static_cast<std::uint16_t>((std::min)(attributes.level, 65535U)),
        bytes, 58U);
    write_u16((attributes.is_service ||
        (attributes.is_guard && !nation_selected)) ? 1U : 0U, bytes, 62U);
    packet[68U] = std::byte{0U}; // SPAWN_NORMAL
    packet[69U] = static_cast<std::byte>(attributes.elevation & 0xffU);
    packet[70U] = static_cast<std::byte>(attributes.head_id & 0xffU);
    packet[71U] = static_cast<std::byte>(attributes.leg_id & 0xffU);
    packet[74U] = static_cast<std::byte>(attributes.mob_type & 0xffU);
    write_u16(static_cast<std::uint16_t>(attributes.internal_name_id & 0xffffU),
        bytes, 76U);
    return packet;
}

[[nodiscard]] std::vector<std::byte> make_npc_spawn_packet(
        const data::NpcDefinition& npc) {
    constexpr std::size_t packet_size = 508U;
    if (npc.id > 65535U) return {};
    std::vector<std::byte> packet(packet_size);
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet_size);
    header.client_index = static_cast<std::uint16_t>(npc.id);
    header.opcode = create_mob_opcode;
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), packet.begin());
    const auto bytes = std::span<std::byte>{packet};
    std::copy_n(reinterpret_cast<const std::byte*>(npc.name.data()),
        (std::min<std::size_t>)(npc.name.size(), 16U), packet.begin() + 12);
    for (std::size_t slot = 0U; slot < npc.equipment.size(); ++slot)
        write_u16(npc.equipment[slot], bytes, 28U + slot * 2U);
    write_f32(npc.position_x, bytes, 56U);
    write_f32(npc.position_y, bytes, 60U);
    write_u32(npc.rotation, bytes, 64U);
    write_u32(npc.max_hp, bytes, 68U);
    write_u32(npc.max_hp, bytes, 72U);
    write_u32((std::min)(npc.current_hp, npc.max_hp), bytes, 76U);
    write_u32((std::min)(npc.current_mp, npc.max_hp), bytes, 80U);
    packet[84U] = std::byte{0x28U};
    packet[85U] = static_cast<std::byte>(
        (std::min<std::uint16_t>)(npc.move_speed, 255U));
    packet[86U] = std::byte{0U}; // SPAWN_NORMAL
    for (std::size_t i = 0U; i < npc.sizes.size(); ++i)
        packet[87U + i] = static_cast<std::byte>(npc.sizes[i]);
    packet[91U] = std::byte{1U};
    write_u16(1U, bytes, 92U); // NPC EffectType
    std::copy_n(reinterpret_cast<const std::byte*>(npc.title.data()),
        (std::min<std::size_t>)(npc.title.size(), 32U), packet.begin() + 456);
    return packet;
}

[[nodiscard]] std::array<std::byte, 84U> make_npc_option_packet(
        const std::uint32_t option, const data::GameTables& tables) {
    std::array<std::byte, 84U> packet{};
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = 0x3575U;
    header.opcode = 0x0112U;
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), packet.begin());
    const auto bytes = std::span<std::byte>{packet};
    write_u32(option, bytes, 12U);

    std::string_view text;
    std::uint32_t color = 0xffffffffU;
    switch (option) {
    case 8U: text = "Fechar"; color = 0xffeb5a5aU; break;
    case 21U: text = "Menu"; color = 0xff7fc1f4U; break;
    case 67U: text = "Ir para Ursula"; color = 0xffffdb4dU; break;
    case 68U: text = "Ir para Basilan [2500 gold]"; color = 0xffe6b800U; break;
    case 69U: text = "Ir para Regenchain"; color = 0xffffdb4dU; break;
    case 70U: text = "Desfazer aliança"; color = 0xffeb5a5aU; break;
    case 71U: text = "Remover aliado 01"; color = 0xffeb5a5aU; break;
    case 72U: text = "Remover aliado 02"; color = 0xffeb5a5aU; break;
    case 73U: text = "Remover aliado 03"; color = 0xffeb5a5aU; break;
    case 74U: text = "Sair da aliança"; color = 0xffeb5a5aU; break;
    case 75U: text = "Voltar para Regenchain"; color = 0xff2eb82eU; break;
    case 76U: text = "[Defesa] Torre 01"; color = 0xff33adffU; break;
    case 77U: text = "[Defesa] Torre 02"; color = 0xff33adffU; break;
    case 78U: text = "[Defesa] Torre 03"; color = 0xff33adffU; break;
    default:
        if (option < tables.npc_option_text.size()) {
            const auto& stored_text = tables.npc_option_text[option];
            const auto end = std::find(stored_text.begin(), stored_text.end(), '\0');
            text = {stored_text.data(), static_cast<std::size_t>(end - stored_text.begin())};
        }
        break;
    }
    if (text.empty() && option < tables.npc_option_text.size()) {
        const auto& stored_text = tables.npc_option_text[option];
        const auto end = std::find(stored_text.begin(), stored_text.end(), '\0');
        text = {stored_text.data(), static_cast<std::size_t>(end - stored_text.begin())};
    }
    if (!text.empty()) {
        std::copy_n(reinterpret_cast<const std::byte*>(text.data()),
            (std::min<std::size_t>)(text.size(), 64U), packet.begin() + 16);
    }
    write_u32(color, bytes, 80U);
    return packet;
}

[[nodiscard]] std::vector<std::byte> make_player_skills_packet(
        const database::CharacterRecord& character, const std::uint16_t client_id,
        const std::uint32_t npc_index = 0U) {
    std::vector<std::byte> packet(96U);
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = client_id;
    header.opcode = send_skills_opcode;
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), packet.begin());
    const auto bytes = std::span<std::byte>{packet};
    write_u16(static_cast<std::uint16_t>(npc_index), bytes, 12U);
    if (npc_index != 0U) write_u16(0x000bU, bytes, 14U);
    for (std::size_t i = 0U; i < 40U; ++i) {
        const auto& skill = character.skills[i + 6U];
        if (skill[0] != 0U)
            write_u16(skill[0], bytes, 16U + i * 2U);
    }
    return packet;
}

[[nodiscard]] std::array<std::byte, 20U> make_remove_mob_packet(
        const std::uint16_t mob_id) {
    std::array<std::byte, 20U> packet{};
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = 0x7535U;
    header.opcode = remove_mob_opcode;
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), packet.begin());
    const auto bytes = std::span<std::byte>{packet};
    write_u32(mob_id, bytes, 12U);
    return packet;
}

[[nodiscard]] std::vector<std::byte> make_client_message_packet(
        const std::string_view message, const std::uint16_t client_id,
        const std::uint8_t type = 16U) {
    std::vector<std::byte> packet(144U);
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = client_id;
    header.opcode = 0x0984U;
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), packet.begin());
    packet[13U] = static_cast<std::byte>(type);
    const auto length = std::min<std::size_t>(message.size(), 127U);
    packet[16U] = static_cast<std::byte>(length);
    std::copy_n(reinterpret_cast<const std::byte*>(message.data()), length,
        packet.begin() + 17);
    return packet;
}

[[nodiscard]] std::vector<std::byte> make_current_hp_mp_packet(
        const database::CharacterRecord& character, const std::uint16_t client_id,
        const data::GameTables& tables, const bool update = false) {
    std::vector<std::byte> packet(32U);
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = client_id;
    header.opcode = current_hp_mp_opcode;
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), packet.begin());
    const auto bytes = std::span<std::byte>{packet};
    const auto [max_hp, max_mp] = estimate_max_hp_mp(character, tables);
    write_u32(max_hp, bytes, 12U);
    write_u32((std::min)(character.current_hp, max_hp), bytes, 16U);
    write_u32(max_mp, bytes, 20U);
    write_u32((std::min)(character.current_mp, max_mp), bytes, 24U);
    if (update) write_u32(1U, bytes, 28U);
    return packet;
}

[[nodiscard]] std::vector<std::byte> make_refresh_buffs_packet(
        const database::CharacterRecord& character, const std::uint16_t client_id,
        const data::GameTables& tables) {
    constexpr std::size_t buff_capacity = 40U;
    constexpr std::size_t packet_size = 12U + buff_capacity * 6U;
    std::vector<std::byte> packet(packet_size);
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = client_id;
    header.opcode = 0x016eU;
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), packet.begin());
    const auto bytes = std::span<std::byte>{packet};
    const auto now = static_cast<std::uint64_t>(std::time(nullptr));
    std::size_t output_slot = 0U;
    for (const auto& buff : character.buffs) {
        const auto skill_id = static_cast<std::size_t>(buff[0]);
        if (skill_id == 0U || skill_id >= tables.skill_definitions.size()) continue;
        const auto duration = static_cast<std::uint64_t>(
            tables.skill_definitions[skill_id].duration);
        if (buff[1] <= now && duration <= now - buff[1]) continue;
        const auto offset = 12U + output_slot * 2U;
        write_u16(static_cast<std::uint16_t>(skill_id), bytes, offset);
        write_u32(static_cast<std::uint32_t>(buff[1] + duration), bytes,
            12U + buff_capacity * 2U + output_slot * 4U);
        if (++output_slot == buff_capacity) break;
    }
    return packet;
}

[[nodiscard]] std::vector<std::byte> make_refresh_level_packet(
        const database::CharacterRecord& character, const std::uint16_t client_id) {
    std::vector<std::byte> packet(24U);
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = client_id;
    header.opcode = refresh_level_opcode;
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), packet.begin());
    const auto bytes = std::span<std::byte>{packet};
    write_u16(static_cast<std::uint16_t>(character.level == 0U
        ? 0U : character.level - 1U), bytes, 12U);
    write_u16(0x00ccU, bytes, 14U);
    write_u64(character.experience, bytes, 16U);
    return packet;
}

[[nodiscard]] std::vector<std::byte> make_refresh_points_packet(
        const database::CharacterRecord& character) {
    std::vector<std::byte> packet(28U);
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = 0x7535U;
    header.opcode = refresh_points_opcode;
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), packet.begin());
    const auto bytes = std::span<std::byte>{packet};
    for (std::size_t i = 0U; i < character.attributes.size(); ++i)
        write_u16(character.attributes[i], bytes, 12U + i * 2U);
    write_u16(character.attributes[5U], bytes, 24U);
    write_u16(character.skill_points, bytes, 26U);
    return packet;
}

[[nodiscard]] std::vector<std::byte> make_character_effect_packet(
        const std::uint16_t client_id, const std::uint32_t effect) {
    std::vector<std::byte> packet(20U);
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = client_id;
    header.opcode = 0x0117U;
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), packet.begin());
    const auto bytes = std::span<std::byte>{packet};
    write_u32(client_id, bytes, 12U);
    write_u32(effect, bytes, 16U);
    return packet;
}

[[nodiscard]] std::vector<std::byte> make_skill_levels_packet(
        const database::CharacterRecord& character,
        const data::GameTables& tables, const std::uint16_t client_id) {
    std::vector<std::byte> packet(136U);
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = client_id;
    header.opcode = 0x0107U;
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), packet.begin());
    const auto bytes = std::span<std::byte>{packet};
    for (std::size_t i = 0U; i < 6U; ++i)
        if (character.skills[i][1] != 0U)
            write_u16(2U, bytes, 12U + i * 2U);
    for (std::size_t i = 0U; i < 40U; ++i) {
        const auto& skill = character.skills[i + 6U];
        if (skill[0] == 0U || skill[1] == 0U) continue;
        const auto table_index = static_cast<std::size_t>(skill[0]) + skill[1] - 1U;
        if (table_index >= tables.skill_definitions.size()) continue;
        const auto exponent = tables.skill_definitions[table_index].level + 1U;
        if (exponent >= 64U) continue;
        const auto raw = static_cast<std::uint64_t>(std::pow(2.0,
            static_cast<double>(exponent)) - 2.0);
        auto value = raw;
        if (i > 0U && character.skills[i + 5U][1] == 16U) ++value;
        const auto offset = 12U + (i + 6U) * 2U;
        if (raw <= 65535U) write_u16(static_cast<std::uint16_t>(value), bytes, offset);
        else if (raw <= 131080U) write_u32(static_cast<std::uint32_t>(value), bytes, offset);
    }
    write_u16(character.skill_points, bytes, 132U);
    write_u16(0xccccU, bytes, 134U);
    return packet;
}

[[nodiscard]] std::array<std::byte, 32U> make_refresh_money_packet(
        const database::CharacterRecord& character,
        const database::AccountRecord& account) {
    std::array<std::byte, 32U> packet{};
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(packet.size());
    header.client_index = 0x7535U;
    header.opcode = 0x0312U;
    const auto encoded = protocol::encode_header(header);
    std::copy(encoded.begin(), encoded.end(), packet.begin());
    write_u64(character.gold, packet, 16U);
    write_u64(account.storage_gold, packet, 24U);
    return packet;
}

struct GameSession final {
    GameSession(const SOCKET client_socket, const std::uint16_t assigned_client_id)
        : socket{client_socket}, client_id{assigned_client_id},
          last_saved_at{std::chrono::steady_clock::now()},
          last_packet_at{std::chrono::steady_clock::now()} {}

    SOCKET socket{INVALID_SOCKET};
    std::uint16_t client_id{};
    std::mutex send_mutex;
    database::AccountRecord account;
    std::vector<database::CharacterRecord> characters;
    std::optional<database::CharacterRecord> selected_character;
    std::unordered_set<std::uint16_t> visible_players;
    std::unordered_set<std::uint32_t> visible_mobs;
    std::uint16_t opened_npc{};
    std::uint32_t opened_npc_option{};
    std::uint32_t current_action{};
    std::chrono::steady_clock::time_point last_saved_at;
    std::chrono::steady_clock::time_point last_packet_at;
    std::chrono::steady_clock::time_point last_shout_at{};
    std::chrono::steady_clock::time_point ping_command_at{};
    std::chrono::steady_clock::time_point last_basic_attack_at{};
    std::unordered_map<std::uint16_t, std::chrono::steady_clock::time_point>
        last_skill_use_at;
    bool has_shouted{};
    bool has_ping_command{};
    std::uint32_t skill_upgraded{};
    std::uint32_t mob_drop_count{};
    std::uint8_t movement_debug_logged{};
    std::uint8_t rotation_debug_logged{};
    std::uint8_t world_packet_debug_logged{};
    std::uint8_t interaction_debug_logged{};
    bool authenticated{};
    bool world_packet_sent{};
    bool entered_world{};
    bool storage_open{};
};

struct MobRuntimeState final {
    std::uint32_t current_hp{};
    std::uint32_t maximum_hp{};
    bool dead{};
    std::chrono::steady_clock::time_point respawn_at{};
    std::uint16_t aggro_target{};
    std::chrono::steady_clock::time_point next_attack_at{};
    float position_x{};
    float position_y{};
    bool returning{};
    std::chrono::steady_clock::time_point next_move_at{};
    bool patrolling_to_destination{true};
    std::chrono::steady_clock::time_point next_patrol_at{};
    std::chrono::steady_clock::time_point next_skill_at{};
    std::uint8_t mob_skill_cursor{};
    std::uint8_t patrol_movement_substeps{};
};

[[nodiscard]] std::optional<std::uint32_t> character_job(
    std::uint16_t class_info) noexcept;

void apply_character_level_award(database::CharacterRecord& character,
        std::uint16_t increment,
        std::vector<std::pair<std::uint16_t, std::uint16_t>>& event_rewards);

[[nodiscard]] bool handle_storage_item_move(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const data::GameTables& tables, GameSession& session) {
    if (request.size() < 20U || !session.entered_world ||
        !session.storage_open || !session.selected_character.has_value()) return true;
    const auto destination_type = read_u16(request, 12U);
    const auto destination_slot = read_u16(request, 14U);
    const auto source_type = read_u16(request, 16U);
    const auto source_slot = read_u16(request, 18U);
    if ((source_type != 1U && source_type != 2U) ||
        (destination_type != 1U && destination_type != 2U) ||
        (source_type == destination_type && source_slot == destination_slot)) return true;

    auto& character = *session.selected_character;
    const auto inventory_slot_is_unlocked = [&character](const std::uint16_t slot) {
        return is_inventory_slot_unlocked(character.inventory, slot);
    };
    const auto storage_slot_unlocked = [&session](const std::uint16_t slot) {
        if (slot >= 80U) return false;
        const auto bag_slot = static_cast<std::size_t>(80U + slot / 20U);
        return session.account.storage_items[bag_slot].item_id != 0U;
    };
    const auto valid_slot = [&inventory_slot_is_unlocked, &storage_slot_unlocked](
            const std::uint16_t type, const std::uint16_t slot) {
        if (type == 1U) return inventory_slot_is_unlocked(slot);
        if (slot < 80U) return storage_slot_unlocked(slot);
        return slot == 84U || slot == 85U;
    };
    if (!valid_slot(source_type, source_slot) ||
        !valid_slot(destination_type, destination_slot)) return true;
    auto& source = source_type == 1U
        ? character.inventory[source_slot] : session.account.storage_items[source_slot];
    auto& destination = destination_type == 1U
        ? character.inventory[destination_slot] : session.account.storage_items[destination_slot];
    if (source.item_id == 0U || source.item_id >= tables.item_definitions.size() ||
        (destination.item_id != 0U && destination.item_id >= tables.item_definitions.size()))
        return true;
    const auto source_item_type = tables.item_definitions[source.item_id].item_type;
    const auto destination_item_type = destination.item_id == 0U ? 0U
        : tables.item_definitions[destination.item_id].item_type;
    const auto source_trade_type = tables.item_definitions[source.item_id].trade_type;
    const auto destination_trade_type = destination.item_id == 0U ? 0U
        : tables.item_definitions[destination.item_id].trade_type;
    if ((source_type == 2U && source_slot >= 84U && source_item_type != 10U) ||
        (destination_type == 2U && destination_slot >= 84U && source_item_type != 10U) ||
        (destination_type == 2U && destination_slot >= 84U &&
            destination_item_type != 0U && destination_item_type != 10U) ||
        (source_type == 1U && destination_type == 2U && source_item_type != 10U &&
            (source_trade_type == 1U ||
             (destination.item_id != 0U && destination_trade_type == 1U))) ||
        (source_type == 2U && destination_type == 1U &&
            destination.item_id != 0U && destination_trade_type == 1U) ||
        (destination.item_id != 0U && source_item_type == 8U &&
            destination_item_type == 8U)) return true;

    auto updated_source = source;
    auto updated_destination = destination;
    if (source.item_id == destination.item_id && destination.item_id != 0U &&
        tables.item_definitions[source.item_id].can_group != 0U) {
        if (source.refine > 1000U || destination.refine > 1000U) return true;
        const auto total = source.refine + destination.refine;
        if (source.refine == 1000U || destination.refine == 1000U) {
            std::swap(updated_source, updated_destination);
        } else if (total > 1000U) {
            updated_source.refine = 1000U;
            updated_destination.refine = total - 1000U;
        } else {
            updated_source.refine = total;
            updated_destination = {};
        }
    } else {
        std::swap(updated_source, updated_destination);
    }
    const std::vector<database::CharacterItemPlacement> updates{
        {static_cast<std::uint8_t>(source_type), source_slot, updated_source},
        {static_cast<std::uint8_t>(destination_type), destination_slot,
            updated_destination}};
    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(character.id, character.gold, updates,
            {}, std::nullopt, std::nullopt, std::nullopt, std::nullopt,
            {}, {}, std::nullopt, {}, session.account.id);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika storage item-move persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    source = updated_source;
    destination = updated_destination;
    auto destination_refresh = make_refresh_item_packet(destination_type,
        destination_slot, destination);
    auto source_refresh = make_refresh_item_packet(source_type, source_slot, source);
    return send_encrypted(socket, destination_refresh) &&
        send_encrypted(socket, source_refresh);
}

[[nodiscard]] bool handle_inventory_move(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const data::GameTables& tables, GameSession& session,
        const std::function<std::optional<std::pair<database::CharacterItem,
            database::CharacterItem>>()>& apply_item_move,
        const std::function<std::optional<std::pair<database::CharacterItem,
            database::CharacterItem>>(std::uint16_t, std::uint16_t,
                std::uint16_t, std::uint16_t)>& apply_stack_merge,
        const std::function<bool()>& refresh_equipment_status,
        const std::function<bool()>& refresh_equipment_spawn) {
    if (request.size() < 20U || !session.selected_character.has_value()) return true;
    const auto destination_type = read_u16(request, 12U);
    const auto destination_slot = read_u16(request, 14U);
    const auto source_type = read_u16(request, 16U);
    const auto source_slot = read_u16(request, 18U);
    constexpr std::uint16_t equipment_type = 0U;
    constexpr std::uint16_t inventory_type = 1U;
    if (source_type > inventory_type || destination_type > inventory_type ||
        (source_type == destination_type && source_slot == destination_slot)) return true;

    auto& character = *session.selected_character;
    const auto valid_slot = [](const std::uint16_t type, const std::uint16_t slot) {
        return type == inventory_type ? slot < 60U : slot > 1U && slot < 16U;
    };
    if (!valid_slot(source_type, source_slot) ||
        !valid_slot(destination_type, destination_slot)) return true;

    const auto bag_unlocked = [&character](const std::uint16_t slot) {
        return is_inventory_slot_unlocked(character.inventory, slot);
    };
    if ((source_type == inventory_type && !bag_unlocked(source_slot)) ||
        (destination_type == inventory_type && !bag_unlocked(destination_slot)))
        return true;

    auto& source = source_type == inventory_type
        ? character.inventory[source_slot] : character.equipment[source_slot];
    auto& destination = destination_type == inventory_type
        ? character.inventory[destination_slot] : character.equipment[destination_slot];
    std::clog << "[game] item move validated client=" << session.client_id
              << " from=" << source_type << ':' << source_slot
              << " item=" << source.item_id
              << " to=" << destination_type << ':' << destination_slot
              << " item=" << destination.item_id
              << " bags=" << character.inventory[60U].item_id << ','
              << character.inventory[61U].item_id << ','
              << character.inventory[62U].item_id << ','
              << character.inventory[63U].item_id << std::endl;
    if (source.item_id == 0U || source.item_id >= tables.item_definitions.size() ||
        (destination.item_id != 0U && destination.item_id >= tables.item_definitions.size()))
        return true;
    const bool merge_stacks = source_type == inventory_type &&
        destination_type == inventory_type && source.item_id == destination.item_id &&
        tables.item_definitions[source.item_id].can_group != 0U;
    const auto special_item = [&tables](const std::uint32_t item_id) {
        if (item_id == 0U) return false;
        const auto type = tables.item_definitions[item_id].item_type;
        return type == 8U || type == 9U || type == 10U;
    };
    if (special_item(source.item_id) ||
        (destination.item_id != 0U &&
            special_item(destination.item_id)))
        return true; // Pets, mounts and Prans have additional spawn/effect behavior.

    const auto equip_slot = [&tables](const std::uint32_t item_id) {
        const auto type = tables.item_definitions[item_id].item_type;
        if (type == 50U || type == 52U) return std::uint16_t{15U};
        if (type > 0U && type < 16U) return type;
        if (type > 1000U && type < 1011U) return std::uint16_t{6U};
        return std::uint16_t{0U};
    };
    const auto class_bucket = [](const std::uint16_t class_info) {
        if (class_info >= 1U && class_info <= 9U) return 0;
        if (class_info >= 11U && class_info <= 19U) return 1;
        if (class_info >= 21U && class_info <= 29U) return 2;
        if (class_info >= 31U && class_info <= 39U) return 3;
        if (class_info >= 41U && class_info <= 49U) return 4;
        if (class_info >= 51U && class_info <= 59U) return 5;
        return -1;
    };
    const auto can_use = [&character, &tables, &class_bucket](
            const std::uint32_t item_id) {
        const auto& definition = tables.item_definitions[item_id];
        if (definition.level > character.level) return false;
        return definition.class_id == 0U ||
            class_bucket(definition.class_id) == class_bucket(character.class_info);
    };
    if (source_type == inventory_type && destination_type == equipment_type) {
        if (equip_slot(source.item_id) != destination_slot || !can_use(source.item_id))
            return true;
    } else if (source_type == equipment_type && destination_type == inventory_type) {
        if (equip_slot(source.item_id) != source_slot) return true;
        if (destination.item_id != 0U &&
            (equip_slot(destination.item_id) != source_slot || !can_use(destination.item_id)))
            return true;
    } else if (source_type == inventory_type && destination_type == inventory_type) {
        // Equal stackable items combine below; other inventory items are swapped.
    } else {
        return true;
    }

    std::optional<std::pair<database::CharacterItem, database::CharacterItem>> updated_items;
    try {
        database::MysqlConnection database{database_config};
        if (merge_stacks) {
            if (source.refine > 1000U || destination.refine > 1000U) return true;
            const auto source_quantity = static_cast<std::uint16_t>(source.refine);
            const auto destination_quantity = static_cast<std::uint16_t>(destination.refine);
            if (source_quantity == 0U || destination_quantity == 0U) return true;
            if (source_quantity == 1000U || destination_quantity == 1000U) {
                if (!database.move_character_item(character.id, source_type, source_slot,
                        destination_type, destination_slot)) return true;
                updated_items = apply_item_move();
            } else {
                const auto total = static_cast<std::uint32_t>(source_quantity) +
                    destination_quantity;
                const auto new_source_quantity = static_cast<std::uint16_t>(
                    (std::min)(total, 1000U));
                const auto new_destination_quantity = static_cast<std::uint16_t>(
                    total <= 1000U ? 0U : total - 1000U);
                if (!database.merge_inventory_stack(character.id, source_slot,
                        destination_slot, source_quantity, destination_quantity,
                        new_source_quantity, new_destination_quantity)) return true;
                updated_items = apply_stack_merge(source_quantity,
                    destination_quantity, new_source_quantity, new_destination_quantity);
            }
        } else {
            if (!database.move_character_item(character.id, source_type, source_slot,
                    destination_type, destination_slot)) return true;
            updated_items = apply_item_move();
        }
    } catch (const std::exception& error) {
        std::clog << "[game] item move persistence failed client="
                  << session.client_id << " error=" << error.what() << std::endl;
        auto message = make_client_message_packet(
            "Nao foi possivel salvar a movimentacao do item. Tente novamente.",
            session.client_id);
        return send_encrypted(socket, message);
    } catch (...) {
        std::clog << "[game] item move persistence failed client="
                  << session.client_id << " error=unknown" << std::endl;
        auto message = make_client_message_packet(
            "Nao foi possivel salvar a movimentacao do item. Tente novamente.",
            session.client_id);
        return send_encrypted(socket, message);
    }

    if (!updated_items.has_value()) return false;
    auto destination_update = make_refresh_item_packet(destination_type,
        destination_slot, updated_items->second);
    auto source_update = make_refresh_item_packet(source_type,
        source_slot, updated_items->first);
    if (!send_encrypted(socket, destination_update) ||
        !send_encrypted(socket, source_update)) return false;
    const bool equipment_changed = source_type == equipment_type ||
        destination_type == equipment_type;
    if (equipment_changed && !refresh_equipment_status()) return false;
    const bool refresh_spawn = (source_type == equipment_type &&
            source_slot >= 2U && source_slot <= 7U) ||
        (destination_type == equipment_type && destination_slot >= 2U &&
            destination_slot <= 7U);
    return !refresh_spawn || refresh_equipment_spawn();
}

[[nodiscard]] bool send_to_session(GameSession& session,
        std::vector<std::byte>& packet) {
    const std::lock_guard lock{session.send_mutex};
    return send_encrypted(session.socket, packet);
}

class ChannelRuntime final {
public:
    ChannelRuntime(config::DatabaseConfig config, const data::WorldData& world_data,
            const std::uint16_t experience_multiplier)
        : database_config_{std::move(config)}, world_data_{&world_data},
          experience_multiplier_{experience_multiplier} {
        const auto now = std::chrono::steady_clock::now();
        mob_states_.reserve(world_data.mob_spawns.size());
        for (const auto& spawn : world_data.mob_spawns) {
            if (spawn.client_id > 65535U ||
                spawn.mob_template_id >= world_data.mob_templates.size()) continue;
            const auto& mob_template = world_data.mob_templates[spawn.mob_template_id];
            if (!mob_template.attributes.has_value() ||
                !mob_template.attributes->active_to_spawn) continue;
            const auto hp = mob_template.attributes->initial_hp;
            mob_states_.try_emplace(spawn.client_id,
                MobRuntimeState{hp, hp, false, {}, 0U, {}, spawn.initial_x,
                    spawn.initial_y, false, {}, true,
                    now + std::chrono::seconds{spawn.initial_move_wait}, {}, 0U});
        }
    }

    [[nodiscard]] std::uint32_t visible_mob_hp(const std::uint32_t mob_id) {
        const std::lock_guard lock{clients_mutex_};
        const auto state = mob_states_.find(mob_id);
        if (state == mob_states_.end()) return 0U;
        if (state->second.dead && state->second.respawn_at <=
                std::chrono::steady_clock::now()) {
            state->second.current_hp = state->second.maximum_hp;
            state->second.dead = false;
            state->second.aggro_target = 0U;
            state->second.next_attack_at = {};
        }
        return state->second.dead ? 0U : state->second.current_hp;
    }

    [[nodiscard]] data::MobSpawn current_mob_spawn(
            const data::MobSpawn& spawn) {
        auto current = spawn;
        const std::lock_guard lock{clients_mutex_};
        const auto state = mob_states_.find(spawn.client_id);
        if (state != mob_states_.end()) {
            current.initial_x = state->second.position_x;
            current.initial_y = state->second.position_y;
        }
        return current;
    }

    void tick_mob_ai(const data::GameTables& tables) {
        struct AttackNotice final {
            std::shared_ptr<GameSession> target;
            std::uint16_t mob_id{};
            std::uint16_t skill_id{};
            std::uint8_t target_animation{26U};
            float mob_x{};
            float mob_y{};
            std::uint32_t mob_hp{};
            std::uint32_t damage{};
            std::uint8_t damage_type{};
            database::CharacterRecord character;
        };
        struct MovementNotice final {
            std::uint16_t mob_id{};
            const data::MobSpawn* spawn{};
            float x{};
            float y{};
            std::uint32_t hp{};
            std::uint8_t speed{22U};
            bool refresh_spawn{};
            std::vector<std::shared_ptr<GameSession>> recipients;
            std::vector<std::shared_ptr<GameSession>> entering;
            std::vector<std::shared_ptr<GameSession>> leaving;
        };
        std::vector<AttackNotice> notices;
        std::vector<MovementNotice> movements;
        const auto now = std::chrono::steady_clock::now();
        {
            const std::lock_guard lock{clients_mutex_};
            if (now - last_mob_ai_tick_ < std::chrono::milliseconds{250}) return;
            last_mob_ai_tick_ = now;
            const auto queue_movement = [&](const data::MobSpawn& spawn,
                    MobRuntimeState& state, const std::uint8_t speed = 22U) {
                MovementNotice movement;
                movement.mob_id = static_cast<std::uint16_t>(spawn.client_id);
                movement.spawn = &spawn;
                movement.x = state.position_x;
                movement.y = state.position_y;
                movement.hp = state.current_hp;
                movement.speed = speed;
                for (const auto& [id, session] : clients_) {
                    (void)id;
                    if (!session->entered_world ||
                        !session->selected_character.has_value()) continue;
                    const bool was_visible = session->visible_mobs.contains(
                        spawn.client_id);
                    const bool in_range = distance(
                        session->selected_character->position_x,
                        session->selected_character->position_y,
                        state.position_x, state.position_y) <= watch_distance;
                    if (in_range) {
                        session->visible_mobs.insert(spawn.client_id);
                        (was_visible ? movement.recipients : movement.entering)
                            .push_back(session);
                    } else if (was_visible) {
                        session->visible_mobs.erase(spawn.client_id);
                        movement.leaving.push_back(session);
                    }
                }
                movements.push_back(std::move(movement));
            };
            for (const auto& spawn : world_data_->mob_spawns) {
                const auto state_it = mob_states_.find(spawn.client_id);
                if (state_it == mob_states_.end() || state_it->second.dead ||
                    spawn.mob_template_id >= world_data_->mob_templates.size()) continue;
                auto& runtime_state = state_it->second;
                const auto& mob = world_data_->mob_templates[spawn.mob_template_id];
                if (!mob.attributes.has_value()) continue;
                auto player_it = clients_.end();
                if (runtime_state.aggro_target != 0U) {
                    player_it = clients_.find(runtime_state.aggro_target);
                    if (player_it == clients_.end() || !player_it->second->entered_world ||
                        !player_it->second->selected_character.has_value() ||
                        player_it->second->selected_character->current_hp == 0U) {
                        player_it = clients_.end();
                    }
                }
                if (player_it != clients_.end()) {
                    const auto& target = *player_it->second->selected_character;
                    if (distance(target.position_x, target.position_y,
                            spawn.initial_x, spawn.initial_y) > 40.0F) {
                        player_it = clients_.end();
                    }
                }
                if (runtime_state.aggro_target != 0U && player_it == clients_.end()) {
                    std::uint16_t nearby_target{};
                    float closest = 40.0F;
                    for (const auto& [id, candidate] : clients_) {
                        if (id == runtime_state.aggro_target || !candidate->entered_world ||
                            !candidate->selected_character.has_value() ||
                            candidate->selected_character->current_hp == 0U) continue;
                        const auto candidate_distance = distance(
                            candidate->selected_character->position_x,
                            candidate->selected_character->position_y,
                            spawn.initial_x, spawn.initial_y);
                        if (candidate_distance < closest) {
                            closest = candidate_distance;
                            nearby_target = id;
                        }
                    }
                    runtime_state.aggro_target = nearby_target;
                    if (nearby_target != 0U) {
                        player_it = clients_.find(nearby_target);
                        runtime_state.returning = false;
                    } else {
                        runtime_state.returning = true;
                    }
                }

                if (mob.attributes->is_guard && player_it == clients_.end()) {
                    runtime_state.aggro_target = 0U;
                    runtime_state.returning = false;
                    runtime_state.position_x = spawn.initial_x;
                    runtime_state.position_y = spawn.initial_y;
                    continue;
                }

                float destination_x = spawn.initial_x;
                float destination_y = spawn.initial_y;
                float stop_distance = 1.5F;
                if (player_it != clients_.end()) {
                    runtime_state.returning = false;
                    const auto& target = *player_it->second->selected_character;
                    destination_x = target.position_x;
                    destination_y = target.position_y;
                    stop_distance = 3.0F;
                } else if (!runtime_state.returning) {
                    if (runtime_state.next_patrol_at > now) continue;
                    destination_x = runtime_state.patrolling_to_destination
                        ? spawn.destination_x : spawn.initial_x;
                    destination_y = runtime_state.patrolling_to_destination
                        ? spawn.destination_y : spawn.initial_y;
                    const auto patrol_distance = distance(runtime_state.position_x,
                        runtime_state.position_y, destination_x, destination_y);
                    if (patrol_distance <= 1.0F) {
                        runtime_state.position_x = destination_x;
                        runtime_state.position_y = destination_y;
                        runtime_state.patrolling_to_destination =
                            !runtime_state.patrolling_to_destination;
                        runtime_state.patrol_movement_substeps = 0U;
                        runtime_state.next_patrol_at = now +
                            std::chrono::seconds{spawn.initial_move_wait};
                        queue_movement(spawn, runtime_state);
                    } else {
                        // Delphi advances each axis by 1.5 units and only
                        // broadcasts after every second movement tick.
                        const auto advance_axis = [](const float current,
                                const float destination) {
                            const auto delta = destination - current;
                            if (std::abs(delta) <= 1.5F) return destination;
                            return current + std::copysign(1.5F, delta);
                        };
                        runtime_state.position_x = advance_axis(
                            runtime_state.position_x, destination_x);
                        runtime_state.position_y = advance_axis(
                            runtime_state.position_y, destination_y);
                        runtime_state.next_patrol_at = now +
                            std::chrono::milliseconds{250};
                        if (++runtime_state.patrol_movement_substeps >= 2U) {
                            runtime_state.patrol_movement_substeps = 0U;
                            queue_movement(spawn, runtime_state);
                        }
                    }
                    continue;
                }
                const auto mob_distance = distance(runtime_state.position_x,
                    runtime_state.position_y, destination_x, destination_y);
                if (mob_distance > stop_distance && runtime_state.next_move_at <= now) {
                    const auto advance_axis = [](const float current,
                            const float destination) {
                        const auto delta = destination - current;
                        if (std::abs(std::round(delta)) < 3.0F) return current;
                        return current + std::copysign(2.0F, delta);
                    };
                    runtime_state.position_x = advance_axis(
                        runtime_state.position_x, destination_x);
                    runtime_state.position_y = advance_axis(
                        runtime_state.position_y, destination_y);
                    runtime_state.next_move_at = now + std::chrono::milliseconds{500};
                    queue_movement(spawn, runtime_state, 40U);
                }
                if (player_it == clients_.end()) {
                    if (distance(runtime_state.position_x, runtime_state.position_y,
                            spawn.initial_x, spawn.initial_y) <= 2.0F) {
                        runtime_state.position_x = spawn.initial_x;
                        runtime_state.position_y = spawn.initial_y;
                        runtime_state.returning = false;
                        runtime_state.patrolling_to_destination = true;
                        runtime_state.next_patrol_at = now +
                            std::chrono::seconds{spawn.initial_move_wait};
                        const bool restore_hp = runtime_state.current_hp <
                            runtime_state.maximum_hp;
                        runtime_state.current_hp = runtime_state.maximum_hp;
                        if (restore_hp) {
                            MovementNotice refresh;
                            refresh.mob_id = static_cast<std::uint16_t>(spawn.client_id);
                            refresh.spawn = &spawn;
                            refresh.x = spawn.initial_x;
                            refresh.y = spawn.initial_y;
                            refresh.hp = runtime_state.current_hp;
                            refresh.refresh_spawn = true;
                            for (const auto& [id, session] : clients_) {
                                (void)id;
                                if (session->entered_world && session->visible_mobs
                                        .contains(spawn.client_id))
                                    refresh.recipients.push_back(session);
                            }
                            movements.push_back(std::move(refresh));
                        }
                    }
                    continue;
                }
                if (mob_distance > stop_distance || runtime_state.next_attack_at > now)
                    continue;
                auto& target = *player_it->second->selected_character;
                runtime_state.next_attack_at = now + std::chrono::seconds{2};
                const auto combat = calculate_combat_status(target, tables);
                const std::array<std::uint32_t, 5U> mob_skills{
                    mob.attributes->skill_1, mob.attributes->skill_2,
                    mob.attributes->skill_3, mob.attributes->skill_4,
                    mob.attributes->skill_5};
                const bool has_mob_skills = std::any_of(mob_skills.begin(),
                    mob_skills.end(), [](const auto id) { return id != 0U; });
                const data::SkillDefinition* mob_skill{};
                std::uint16_t mob_skill_id{};
                if (has_mob_skills && runtime_state.next_skill_at <= now) {
                    runtime_state.next_skill_at = now + std::chrono::seconds{4};
                    for (std::size_t attempt = 0U; attempt < mob_skills.size(); ++attempt) {
                        const auto slot = runtime_state.mob_skill_cursor % mob_skills.size();
                        runtime_state.mob_skill_cursor = static_cast<std::uint8_t>(
                            (slot + 1U) % mob_skills.size());
                        const auto id = mob_skills[slot];
                        if (id == 0U || id >= tables.skill_definitions.size()) continue;
                        const auto& candidate = tables.skill_definitions[id];
                        const bool has_effects = std::any_of(candidate.effects.begin(),
                            candidate.effects.end(), [](const auto effect) {
                                return effect != 0;
                            });
                        if (candidate.success_rate != 1U || candidate.range != 0U ||
                            candidate.cast_time != 0U || candidate.buff_debuff != 0U ||
                            candidate.duration != 0U || has_effects) continue;
                        mob_skill = &candidate;
                        mob_skill_id = static_cast<std::uint16_t>(id);
                        break;
                    }
                }
                const auto target_job = character_job(target.class_info).value_or(4U);
                const bool target_physical = target_job <= 3U;
                const auto defense = static_cast<std::uint32_t>(target_physical
                    ? combat.physical_defense >> 3U
                    : combat.magical_defense >> 3U);
                const auto attack_value = static_cast<std::uint64_t>(
                    mob.attributes->physical_attack / 2U) +
                    (mob_skill != nullptr ? mob_skill->damage : 0U);
                const auto attack = static_cast<std::uint32_t>(
                    (std::min<std::uint64_t>)(attack_value,
                        (std::numeric_limits<std::uint32_t>::max)()));
                const auto reduced = attack > defense ? attack - defense : 1U;
                static thread_local std::mt19937 random_engine{std::random_device{}()};
                const auto roll = std::uniform_int_distribution<unsigned>{1U, 100U}
                    (random_engine);
                std::uint8_t damage_type = 0U; // TDamageType.Normal
                std::uint32_t damage = reduced +
                    std::uniform_int_distribution<std::uint32_t>{17U, 45U}(random_engine);
                if (roll >= 2U && roll <= 15U) {
                    damage = 0U;
                    damage_type = 8U; // TDamageType.Miss
                } else if (roll <= 30U) {
                    damage = static_cast<std::uint32_t>(damage * 1.5);
                    damage_type = 1U; // TDamageType.Critical
                }
                target.current_hp = damage >= target.current_hp
                    ? 0U : target.current_hp - damage;
                notices.push_back({player_it->second,
                    static_cast<std::uint16_t>(spawn.client_id), mob_skill_id,
                    static_cast<std::uint8_t>(mob_skill != nullptr
                        ? mob_skill->target_animation : 26U), runtime_state.position_x,
                    runtime_state.position_y, runtime_state.current_hp, damage,
                    damage_type, target});
            }
        }
        for (auto& movement : movements) {
            if (movement.refresh_spawn) {
                auto spawn = *movement.spawn;
                spawn.initial_x = movement.x;
                spawn.initial_y = movement.y;
                const auto& mob_template = world_data_->mob_templates[
                    spawn.mob_template_id];
                for (const auto& recipient : movement.recipients) {
                    auto update = make_world_mob_packet(spawn, mob_template,
                        movement.hp, recipient->account.nation != 0U);
                    if (!update.empty() && !send_to_session(*recipient, update))
                        OutputDebugStringA("Aika returning mob refresh failed.\n");
                }
                continue;
            }
            std::vector<std::byte> packet(32U);
            protocol::PacketHeader header{};
            header.size = static_cast<std::uint16_t>(packet.size());
            header.client_index = movement.mob_id;
            header.opcode = movement_opcode;
            const auto encoded = protocol::encode_header(header);
            std::copy(encoded.begin(), encoded.end(), packet.begin());
            write_f32(movement.x, packet, 12U);
            write_f32(movement.y, packet, 16U);
            packet[26U] = std::byte{0U}; // MOVE_NORMAL
            packet[27U] = static_cast<std::byte>(movement.speed);
            for (const auto& recipient : movement.recipients) {
                auto update = packet;
                if (!send_to_session(*recipient, update))
                    OutputDebugStringA("Aika mob movement packet delivery failed.\n");
            }
            for (const auto& recipient : movement.entering) {
                auto spawn = *movement.spawn;
                spawn.initial_x = movement.x;
                spawn.initial_y = movement.y;
                const auto& mob_template = world_data_->mob_templates[
                    spawn.mob_template_id];
                auto update = make_world_mob_packet(spawn, mob_template,
                    movement.hp, recipient->account.nation != 0U);
                if (!update.empty() && !send_to_session(*recipient, update))
                    OutputDebugStringA("Aika mob entering spawn delivery failed.\n");
            }
            for (const auto& recipient : movement.leaving) {
                const auto remove = make_remove_mob_packet(movement.mob_id);
                std::vector<std::byte> update(remove.begin(), remove.end());
                if (!send_to_session(*recipient, update))
                    OutputDebugStringA("Aika mob leaving removal delivery failed.\n");
            }
        }
        for (auto& notice : notices) {
            try {
                database::MysqlConnection database{database_config_};
                database.save_character_items(notice.character.id,
                    notice.character.gold, {}, {},
                    std::pair{notice.character.current_hp, notice.character.current_mp});
            } catch (const std::exception& error) {
                OutputDebugStringA((std::string{"Aika mob attack HP persistence failed: "} +
                    error.what() + "\n").c_str());
            }
            std::vector<std::byte> packet(84U);
            protocol::PacketHeader header{};
            header.size = static_cast<std::uint16_t>(packet.size());
            header.client_index = notice.mob_id;
            header.opcode = 0x0102U;
            const auto encoded = protocol::encode_header(header);
            std::copy(encoded.begin(), encoded.end(), packet.begin());
            write_u32(notice.skill_id, packet, 12U);
            write_f32(notice.mob_x, packet, 16U);
            write_f32(notice.mob_y, packet, 20U);
            write_u16(notice.mob_id, packet, 28U);
            packet[31U] = std::byte{6U}; // mob attack animation
            write_u32(notice.mob_hp, packet, 44U);
            write_u16(notice.target->client_id, packet, 56U);
            packet[58U] = static_cast<std::byte>(notice.damage_type);
            packet[59U] = static_cast<std::byte>(notice.target_animation);
            write_u64(notice.damage, packet, 60U);
            write_u32(notice.character.current_hp, packet, 72U);
            if (!send_to_visible(*notice.target, packet))
                OutputDebugStringA("Aika mob attack packet delivery failed.\n");
            auto hp_mp = make_current_hp_mp_packet(notice.character,
                notice.target->client_id, tables);
            if (!send_to_session(*notice.target, hp_mp))
                OutputDebugStringA("Aika mob attack HP/MP refresh failed.\n");
        }
    }

    void tick_mob_respawns() {
        struct RespawnNotice final {
            std::shared_ptr<GameSession> session;
            const data::MobSpawn* spawn{};
        };
        std::vector<RespawnNotice> notices;
        const auto now = std::chrono::steady_clock::now();
        {
            const std::lock_guard lock{clients_mutex_};
            if (now - last_mob_tick_ < std::chrono::milliseconds{500}) return;
            last_mob_tick_ = now;
            for (const auto& spawn : world_data_->mob_spawns) {
                const auto state = mob_states_.find(spawn.client_id);
                if (state == mob_states_.end() || !state->second.dead ||
                    state->second.respawn_at > now) continue;
                state->second.current_hp = state->second.maximum_hp;
                state->second.dead = false;
                state->second.aggro_target = 0U;
                state->second.next_attack_at = {};
                state->second.position_x = spawn.initial_x;
                state->second.position_y = spawn.initial_y;
                state->second.returning = false;
                state->second.next_move_at = {};
                state->second.patrolling_to_destination = true;
                state->second.next_patrol_at = now +
                    std::chrono::seconds{spawn.initial_move_wait};
                for (const auto& [id, session] : clients_) {
                    (void)id;
                    if (!session->entered_world ||
                        !session->selected_character.has_value() ||
                        distance(session->selected_character->position_x,
                            session->selected_character->position_y,
                            spawn.initial_x, spawn.initial_y) > watch_distance) continue;
                    if (session->visible_mobs.insert(spawn.client_id).second)
                        notices.push_back({session, &spawn});
                }
            }
        }
        for (const auto& notice : notices) {
            const auto& mob_template = world_data_->mob_templates[
                notice.spawn->mob_template_id];
            const auto state = visible_mob_hp(notice.spawn->client_id);
            if (state == 0U) continue;
            auto packet = make_world_mob_packet(*notice.spawn, mob_template, state,
                notice.session->account.nation != 0U);
            if (packet.empty()) continue;
            if (!send_to_session(*notice.session, packet))
                OutputDebugStringA("Aika mob respawn packet delivery failed.\n");
        }
    }

    [[nodiscard]] bool enter_world(const std::shared_ptr<GameSession>& session,
            const data::GameTables& tables) {
        if (!session->selected_character.has_value()) return false;
        std::vector<std::pair<std::shared_ptr<GameSession>, database::CharacterRecord>> visible;
        const auto character = *session->selected_character;
        {
            const std::lock_guard lock{clients_mutex_};
            for (const auto& [id, other] : clients_) {
                if (id == session->client_id || !other->selected_character.has_value()) continue;
                const auto& other_character = *other->selected_character;
                if (distance(character.position_x, character.position_y,
                        other_character.position_x, other_character.position_y) > watch_distance)
                    continue;
                session->visible_players.insert(id);
                other->visible_players.insert(session->client_id);
                visible.emplace_back(other, other_character);
            }
            clients_[session->client_id] = session;
            session->entered_world = true;
        }

        for (const auto& [other, other_character] : visible) {
            auto to_entering = make_create_mob_packet(other->account,
                other_character, other->client_id, tables);
            if (!send_to_session(*session, to_entering)) return false;
            auto to_existing = make_create_mob_packet(session->account,
                character, session->client_id, tables);
            if (!send_to_session(*other, to_existing)) return false;
        }
        for (const auto& spawn : world_data_->mob_spawns) {
            if (spawn.client_id > 65535U ||
                spawn.mob_template_id >= world_data_->mob_templates.size()) continue;
            const auto current_spawn = current_mob_spawn(spawn);
            if (current_spawn.initial_x < 50.0F || current_spawn.initial_y < 50.0F ||
                distance(character.position_x, character.position_y,
                    current_spawn.initial_x, current_spawn.initial_y) > watch_distance)
                continue;
            const auto& mob_template = world_data_->mob_templates[spawn.mob_template_id];
            if (!mob_template.attributes.has_value() ||
                !mob_template.attributes->active_to_spawn) continue;
            const auto current_hp = visible_mob_hp(spawn.client_id);
            if (current_hp == 0U) continue;
            auto packet = make_world_mob_packet(current_spawn, mob_template,
                current_hp, session->account.nation != 0U);
            if (packet.empty() || !send_to_session(*session, packet)) return false;
            session->visible_mobs.insert(spawn.client_id);
        }
        for (const auto& npc : world_data_->npcs) {
            if (npc.id > 65535U || npc.position_x <= 0.0F || npc.position_y <= 0.0F ||
                distance(character.position_x, character.position_y,
                    npc.position_x, npc.position_y) > watch_distance) continue;
            auto packet = make_npc_spawn_packet(npc);
            if (packet.empty() || !send_to_session(*session, packet)) return false;
            session->visible_mobs.insert(npc.id);
        }
        return true;
    }

    [[nodiscard]] bool open_npc(GameSession& session,
            const std::span<const std::byte> request,
            const data::GameTables& tables) {
        if (request.size() < 24U || !session.entered_world) return true;
        const auto npc_id = read_u32(request, 12U);
        const auto option_type = read_u32(request, 16U);
        if (npc_id == 0U && option_type != 8U) {
            session.opened_npc = 0U;
            session.opened_npc_option = 0U;
            return true;
        }
        if (option_type == 8U) {
            session.opened_npc = 0U;
            session.opened_npc_option = 0U;
            return true;
        }
        const auto npc = std::find_if(world_data_->npcs.begin(),
            world_data_->npcs.end(), [npc_id](const auto& candidate) {
                return candidate.id == npc_id;
            });
        if (npc == world_data_->npcs.end() || npc_id > 65535U ||
            !session.visible_mobs.contains(npc_id)) {
            session.opened_npc = 0U;
            session.opened_npc_option = 0U;
            return true;
        }
        if (option_type == 25U) {
            const float saved_x = std::nearbyint(npc->position_x + 1.0F);
            const float saved_y = std::nearbyint(npc->position_y + 1.0F);
            if (!session.selected_character.has_value() || saved_x <= 0.0F ||
                saved_y <= 0.0F) return true;
            try {
                database::MysqlConnection database{database_config_};
                database.save_character_saved_position(
                    session.selected_character->id, saved_x, saved_y);
            } catch (const std::exception& error) {
                OutputDebugStringA((std::string{"Aika saved location failed: "} +
                    error.what() + "\n").c_str());
                return true;
            }
            session.selected_character->saved_position_x = saved_x;
            session.selected_character->saved_position_y = saved_y;
            session.opened_npc = 0U;
            session.opened_npc_option = 0U;
            auto message = make_client_message_packet("Localização salva.",
                session.client_id);
            return send_to_session(session, message);
        }
        if (option_type == 7U) {
            auto storage = make_storage_packet(session.account, session.client_id);
            if (!send_to_session(session, storage)) return false;
            const auto opened_signal = make_signal_packet(
                session.client_id, 0x0310U, 1U);
            std::vector<std::byte> opened_packet{opened_signal.begin(),
                opened_signal.end()};
            if (!send_to_session(session, opened_packet)) return false;
            for (const auto slot : {84U, 85U}) {
                auto refresh = make_refresh_item_packet(2U,
                    static_cast<std::uint16_t>(slot),
                    session.account.storage_items[slot]);
                if (!send_to_session(session, refresh)) return false;
            }
            session.storage_open = true;
            session.opened_npc = static_cast<std::uint16_t>(npc_id);
            session.opened_npc_option = option_type;
            return true;
        }
        if (option_type == 5U) {
            if (session.opened_npc != npc_id) return true;
            std::vector<std::byte> shop(0x60U);
            protocol::PacketHeader header{};
            header.size = static_cast<std::uint16_t>(shop.size());
            header.client_index = session.client_id;
            header.opcode = 0x0106U;
            const auto encoded = protocol::encode_header(header);
            std::copy(encoded.begin(), encoded.end(), shop.begin());
            write_u16(static_cast<std::uint16_t>(npc_id), shop, 12U);
            write_u16(0x000cU, shop, 14U);
            for (std::size_t slot = 0U; slot < npc->shop_items.size(); ++slot)
                write_u16(npc->shop_items[slot], shop, 16U + slot * 2U);
            session.opened_npc_option = option_type;
            return send_to_session(session, shop);
        }
        if (option_type == 0x1fU || option_type == 0x20U) {
            if (std::find(npc->options.begin(), npc->options.end(), option_type) ==
                    npc->options.end()) return true;
            session.opened_npc = static_cast<std::uint16_t>(npc_id);
            session.opened_npc_option = option_type;
            const auto signal = make_signal_packet(session.client_id,
                0x0310U, option_type);
            std::vector<std::byte> packet{signal.begin(), signal.end()};
            return send_to_session(session, packet);
        }
        if (option_type >= 67U && option_type <= 69U) {
            session.opened_npc = 0U;
            session.opened_npc_option = 0U;
            database::CharacterRecord character;
            {
                const std::lock_guard lock{clients_mutex_};
                if (!session.selected_character.has_value()) return true;
                character = *session.selected_character;
            }
            if (option_type == 68U) {
                if (character.gold < 2500U) return true;
                character.gold -= 2500U;
                try {
                    database::MysqlConnection database{database_config_};
                    database.save_character_items(character.id, character.gold, {});
                } catch (const std::exception& error) {
                    OutputDebugStringA((std::string{"Aika teleport payment failed: "} +
                        error.what() + "\n").c_str());
                    return true;
                }
                if (!replace_character(session, character)) return false;
                const auto money = make_refresh_money_packet(character, session.account);
                std::vector<std::byte> money_packet{money.begin(), money.end()};
                if (!send_to_session(session, money_packet)) return false;
            }
            if (option_type == 67U)
                return teleport_player(session, 3087.0F, 3621.0F, tables);
            if (option_type == 68U)
                return teleport_player(session, 1635.0F, 2218.0F, tables);
            return teleport_player(session, 3399.0F, 564.0F, tables);
        }
        if (option_type != 0U) {
            if (option_type == 1U) {
                const auto signal = make_header_signal_packet(
                    session.client_id, 0x0110U);
                std::vector<std::byte> signal_packet(signal.begin(), signal.end());
                if (!send_to_session(session, signal_packet)) return false;
                for (const auto option : {21U, 8U}) {
                    const auto response = make_npc_option_packet(option, tables);
                    std::vector<std::byte> packet(response.begin(), response.end());
                    if (!send_to_session(session, packet)) return false;
                }
            }
            session.opened_npc = static_cast<std::uint16_t>(npc_id);
            session.opened_npc_option = option_type;
            return true;
        }
        if (session.opened_npc != 0U) {
            const auto close = make_header_signal_packet(session.client_id, 0x010fU);
            std::vector<std::byte> packet(close.begin(), close.end());
            session.opened_npc = 0U;
            session.opened_npc_option = 0U;
            return send_to_session(session, packet);
        }

        const auto signal = make_header_signal_packet(session.client_id, 0x0110U);
        std::vector<std::byte> signal_packet(signal.begin(), signal.end());
        if (!send_to_session(session, signal_packet)) return false;
        const auto data_signal = make_signal_packet(session.client_id, 0x010eU, npc_id);
        std::vector<std::byte> data_packet(data_signal.begin(), data_signal.end());
        if (!send_to_session(session, data_packet)) return false;

        auto options = npc->options;
        switch (npc_id) {
        case 2073U: options[5] = 70U; options[6] = 71U; options[7] = 72U;
                    options[8] = 73U; options[9] = 74U; break;
        case 2093U: options[0] = 67U; options[1] = 68U; options[2] = 8U; break;
        case 2111U: options[0] = 69U; options[1] = 8U; break;
        case 2172U: options[0] = 75U; options[1] = 76U; options[2] = 77U;
                    options[3] = 78U; options[4] = 8U; break;
        case 2196U: options[0] = 69U; options[1] = 8U; break;
        default: break;
        }
        for (const auto option : options) {
            if (option == 0U || option >= 80U) continue;
            const auto response = make_npc_option_packet(option, tables);
            std::vector<std::byte> packet(response.begin(), response.end());
            if (!send_to_session(session, packet)) return false;
        }
        session.opened_npc = static_cast<std::uint16_t>(npc_id);
        session.opened_npc_option = 0U;
        return true;
    }

    [[nodiscard]] bool buy_npc_item(GameSession& session,
            const std::span<const std::byte> request,
            const data::GameTables& tables) {
        if (request.size() < 24U || !session.entered_world ||
            !session.selected_character.has_value()) return true;
        const auto npc_id = read_u32(request, 12U);
        const auto shop_slot = read_u32(request, 16U);
        auto quantity = read_u32(request, 20U);
        if (npc_id != session.opened_npc || shop_slot >= 40U ||
            quantity == 0U || npc_id >= 3335U && npc_id <= 3339U ||
            !session.visible_mobs.contains(npc_id)) return true;
        const auto npc = std::find_if(world_data_->npcs.begin(),
            world_data_->npcs.end(), [npc_id](const auto& candidate) {
                return candidate.id == npc_id;
            });
        if (npc == world_data_->npcs.end()) return true;
        if (npc_id == 2296U) {
            auto message = make_client_message_packet(
                "A loja deste NPC requer status de auxiliar.", session.client_id);
            return send_to_session(session, message);
        }
        const auto item_id = npc->shop_items[shop_slot];
        if (item_id == 0U || item_id >= tables.item_definitions.size()) return true;
        const auto& definition = tables.item_definitions[item_id];

        if (definition.can_group == 0U || item_equip_slot(definition) != 0)
            quantity = 1U;
        quantity = (std::min)(quantity, 1000U);
        std::uint32_t currency_item_id{};
        std::uint64_t currency_item_cost{};
        std::uint64_t honor_cost{};
        std::uint64_t gold_cost{};
        if (definition.price_type != 0U) {
            currency_item_id = item_id == 4204U ? 4204U : definition.price_type;
            currency_item_cost = static_cast<std::uint64_t>(
                definition.price_value) * quantity;
            if (item_id == 4204U) honor_cost = definition.price_type;
        } else if (definition.honor_price > 0U && definition.sell_price == 0U) {
            honor_cost = static_cast<std::uint64_t>(definition.honor_price) * quantity;
        } else if (definition.medal_price > 0U) {
            honor_cost = static_cast<std::uint64_t>(definition.medal_price) * quantity;
            currency_item_id = 4204U;
            currency_item_cost = static_cast<std::uint64_t>(definition.gold_price) * quantity;
        } else if (item_id == 4204U) {
            honor_cost = static_cast<std::uint64_t>(definition.sell_price) * quantity;
        } else {
            if (definition.sell_price <= 1U) return true;
            gold_cost = static_cast<std::uint64_t>(definition.sell_price) * quantity;
        }

        database::CharacterRecord updated;
        {
            const std::lock_guard lock{clients_mutex_};
            const auto active = clients_.find(session.client_id);
            if (active == clients_.end() || active->second.get() != &session ||
                !session.selected_character.has_value()) return true;
            updated = *session.selected_character;
        }
        if (updated.gold < gold_cost || updated.honor < honor_cost) {
            auto message = make_client_message_packet(
                updated.gold < gold_cost ? "Gold insuficiente." : "Honor insuficiente.",
                session.client_id);
            return send_to_session(session, message);
        }

        const auto slot_unlocked = [&updated](const std::uint16_t slot) {
            return slot < 15U || updated.inventory[60U + slot / 15U].item_id != 0U;
        };
        std::vector<std::uint16_t> changed_slots;
        const auto mark_changed = [&changed_slots](const std::uint16_t slot) {
            if (std::find(changed_slots.begin(), changed_slots.end(), slot) ==
                    changed_slots.end()) changed_slots.push_back(slot);
        };
        if (currency_item_cost > 0U) {
            if (currency_item_id >= tables.item_definitions.size()) return true;
            std::optional<std::uint16_t> currency_slot;
            for (std::uint16_t slot = 0U; slot < 60U; ++slot) {
                const auto& candidate = updated.inventory[slot];
                if (slot_unlocked(slot) && candidate.item_id == currency_item_id &&
                    candidate.refine >= currency_item_cost) {
                    currency_slot = slot;
                    break;
                }
            }
            if (!currency_slot.has_value()) {
                auto message = make_client_message_packet(
                    "Voce nao possui a quantidade de medalhas ou itens necessaria.",
                    session.client_id);
                return send_to_session(session, message);
            }
            auto& currency = updated.inventory[*currency_slot];
            if (currency.refine == currency_item_cost) currency = {};
            else currency.refine -= static_cast<std::uint32_t>(currency_item_cost);
            mark_changed(*currency_slot);
        }
        auto remaining = quantity;
        if (definition.can_group != 0U) {
            for (std::uint16_t slot = 0U; slot < 60U && remaining > 0U; ++slot) {
                auto& current = updated.inventory[slot];
                if (!slot_unlocked(slot) || current.item_id != item_id ||
                    current.refine >= 1000U) continue;
                const auto added = (std::min)(remaining, 1000U - current.refine);
                current.refine += added;
                remaining -= added;
                mark_changed(slot);
            }
        }
        while (remaining > 0U) {
            std::optional<std::uint16_t> free_slot;
            for (std::uint16_t slot = 0U; slot < 60U; ++slot) {
                if (slot_unlocked(slot) && updated.inventory[slot].item_id == 0U) {
                    free_slot = slot;
                    break;
                }
            }
            if (!free_slot.has_value()) {
                auto message = make_client_message_packet("Inventario cheio.",
                    session.client_id);
                return send_to_session(session, message);
            }
            auto& created = updated.inventory[*free_slot];
            created = {};
            created.item_id = item_id;
            created.app = item_id;
            created.min = definition.durability;
            created.max = definition.durability;
            const auto amount = definition.can_group != 0U
                ? (std::min)(remaining, 1000U) : 1U;
            created.refine = amount;
            remaining -= amount;
            mark_changed(*free_slot);
        }
        updated.gold -= gold_cost;
        updated.honor -= static_cast<std::uint32_t>(honor_cost);
        std::vector<database::CharacterItemPlacement> placements;
        placements.reserve(changed_slots.size());
        for (const auto slot : changed_slots)
            placements.push_back({1U, slot, updated.inventory[slot]});
        try {
            database::MysqlConnection database{database_config_};
            database.save_character_items(updated.id, updated.gold, placements,
                std::vector<std::uint16_t>{}, std::nullopt, std::nullopt,
                std::nullopt, std::nullopt,
                std::vector<std::pair<std::uint16_t, std::uint16_t>>{},
                std::vector<std::pair<std::uint16_t, std::uint16_t>>{},
                std::nullopt, std::vector<database::CharacterTitle>{},
                std::nullopt, updated.honor);
        } catch (const std::exception& error) {
            OutputDebugStringA((std::string{"Aika NPC purchase failed: "} +
                error.what() + "\n").c_str());
            return true;
        }
        if (!replace_character(session, updated)) return false;
        for (const auto slot : changed_slots) {
            auto refresh = make_refresh_item_packet(1U, slot,
                updated.inventory[slot]);
            if (!send_to_session(session, refresh)) return false;
        }
        if (gold_cost > 0U) {
            const auto money = make_refresh_money_packet(updated, session.account);
            std::vector<std::byte> money_packet{money.begin(), money.end()};
            if (!send_to_session(session, money_packet)) return false;
        }
        if (honor_cost > 0U) {
            std::vector<std::byte> honor_packet(20U);
            protocol::PacketHeader header{};
            header.size = static_cast<std::uint16_t>(honor_packet.size());
            header.client_index = session.client_id;
            header.opcode = 0x012aU;
            const auto encoded = protocol::encode_header(header);
            std::copy(encoded.begin(), encoded.end(), honor_packet.begin());
            write_u32(updated.honor, honor_packet, 12U);
            write_u32(updated.kill_points, honor_packet, 16U);
            return send_to_session(session, honor_packet);
        }
        return true;
    }

    [[nodiscard]] bool sell_npc_item(GameSession& session,
            const std::span<const std::byte> request,
            const data::GameTables& tables) {
        if (request.size() < 20U || !session.entered_world ||
            !session.selected_character.has_value()) return true;
        const auto npc_id = read_u32(request, 12U);
        const auto slot = read_u32(request, 16U);
        if (npc_id != session.opened_npc || slot >= 60U ||
            !session.visible_mobs.contains(npc_id)) return true;
        database::CharacterRecord updated;
        {
            const std::lock_guard lock{clients_mutex_};
            const auto active = clients_.find(session.client_id);
            if (active == clients_.end() || active->second.get() != &session ||
                !session.selected_character.has_value()) return true;
            updated = *session.selected_character;
        }
        if (slot >= 15U && updated.inventory[60U + slot / 15U].item_id == 0U)
            return true;
        const auto item = updated.inventory[slot];
        if (item.item_id == 0U || item.item_id >= tables.item_definitions.size() ||
            item.time > 0U) return true;
        const auto& definition = tables.item_definitions[item.item_id];
        if (definition.sell_price == 0U || definition.item_type == 7U) {
            auto message = make_client_message_packet("Esse item nao pode ser vendido.",
                session.client_id);
            return send_to_session(session, message);
        }
        std::uint64_t proceeds{};
        if (definition.can_group != 0U) {
            const auto base = definition.sell_price < 5U ? definition.sell_price
                : definition.sell_price / ((definition.item_type == 60U ||
                    definition.item_type == 61U) ? 4U : 5U);
            if (base > (std::numeric_limits<std::uint64_t>::max)() /
                    (std::max)(item.refine, 1U)) return true;
            proceeds = static_cast<std::uint64_t>(base) *
                (std::max)(item.refine, 1U);
        } else {
            if (definition.trade_type != 0U || item.max == 0U) {
                auto message = make_client_message_packet("Esse item nao pode ser vendido.",
                    session.client_id);
                return send_to_session(session, message);
            }
            const auto unit = definition.sell_price / 5U;
            proceeds = static_cast<std::uint64_t>(std::nearbyint(
                static_cast<double>(item.min) / item.max * unit));
        }
        if (proceeds == 0U || updated.gold >
                (std::numeric_limits<std::uint64_t>::max)() - proceeds) return true;
        updated.gold += proceeds;
        updated.inventory[slot] = {};
        try {
            database::MysqlConnection database{database_config_};
            database.save_character_items(updated.id, updated.gold,
                {{1U, static_cast<std::uint16_t>(slot), {}}});
        } catch (const std::exception& error) {
            OutputDebugStringA((std::string{"Aika NPC sale failed: "} +
                error.what() + "\n").c_str());
            return true;
        }
        if (!replace_character(session, updated)) return false;
        auto refresh = make_refresh_item_packet(1U,
            static_cast<std::uint16_t>(slot), {});
        if (!send_to_session(session, refresh)) return false;
        const auto money = make_refresh_money_packet(updated, session.account);
        std::vector<std::byte> money_packet{money.begin(), money.end()};
        return send_to_session(session, money_packet);
    }

    [[nodiscard]] bool apply_npc_buff_option(GameSession& session,
            const std::span<const std::byte> request, const std::uint32_t option,
            const data::GameTables& tables) {
        if (request.size() < 24U || !session.entered_world ||
            !session.selected_character.has_value()) return true;
        const auto npc_id = read_u32(request, 12U);
        if (npc_id != session.opened_npc || !session.visible_mobs.contains(npc_id) ||
            (option != 0x23U && option != 0x41U)) return true;
        const auto npc = std::find_if(world_data_->npcs.begin(),
            world_data_->npcs.end(), [npc_id](const auto& candidate) {
                return candidate.id == npc_id;
            });
        if (npc == world_data_->npcs.end() ||
            std::find(npc->options.begin(), npc->options.end(), option) ==
                npc->options.end()) return true;
        static constexpr std::array<std::uint32_t, 4U> lilola_buffs{
            6498U, 6499U, 8500U, 8501U};
        static constexpr std::array<std::uint32_t, 6U> paid_buffs{
            6499U, 202U, 264U, 341U, 5156U, 5186U};
        const auto buff_ids = option == 0x23U
            ? std::span<const std::uint32_t>{lilola_buffs}
            : std::span<const std::uint32_t>{paid_buffs};
        database::CharacterRecord updated;
        {
            const std::lock_guard lock{clients_mutex_};
            const auto active = clients_.find(session.client_id);
            if (active == clients_.end() || active->second.get() != &session ||
                !session.selected_character.has_value() ||
                session.selected_character->current_hp == 0U) return true;
            updated = *session.selected_character;
        }
        constexpr std::uint64_t paid_buff_cost = 50000U;
        if (option == 0x41U && updated.gold < paid_buff_cost) {
            auto message = make_client_message_packet("Gold insuficiente.",
                session.client_id);
            return send_to_session(session, message);
        }

        const auto now = static_cast<std::uint64_t>(std::time(nullptr));
        auto updated_buffs = updated.buffs;
        for (auto& buff : updated_buffs) {
            const auto id = static_cast<std::size_t>(buff[0]);
            if (id == 0U) continue;
            if (id >= tables.skill_definitions.size()) {
                buff = {};
                continue;
            }
            const auto duration = static_cast<std::uint64_t>(
                tables.skill_definitions[id].duration);
            if (buff[1] <= now && duration <= now - buff[1]) buff = {};
        }
        std::vector<std::uint32_t> accepted;
        for (const auto buff_id : buff_ids) {
            if (buff_id == 0U || buff_id >= tables.skill_definitions.size()) continue;
            if (std::find(accepted.begin(), accepted.end(), buff_id) != accepted.end())
                continue;
            const auto group = tables.skill_definitions[buff_id].index;
            for (auto& active_buff : updated_buffs) {
                const auto active_id = static_cast<std::size_t>(active_buff[0]);
                if (active_id != 0U && active_id < tables.skill_definitions.size() &&
                    tables.skill_definitions[active_id].index == group)
                    active_buff = {};
            }
            const auto free_slot = std::find_if(updated_buffs.begin(),
                updated_buffs.end(), [](const auto& entry) {
                    return entry[0] == 0U;
                });
            if (free_slot == updated_buffs.end())
            {
                auto message = make_client_message_packet(
                    "Nao foi possivel adicionar novos buffs. Limite: 60 Buffs.",
                    session.client_id);
                return send_to_session(session, message);
            }
            const auto extra_seconds = option == 0x23U || buff_id != 6499U
                ? 6000U : 0U;
            *free_slot = {buff_id, now + extra_seconds};
            accepted.push_back(buff_id);
        }
        if (accepted.empty()) return true;
        updated.buffs = updated_buffs;
        if (option == 0x41U) updated.gold -= paid_buff_cost;
        try {
            database::MysqlConnection database{database_config_};
            database.save_character_items(updated.id, updated.gold, {}, {},
                std::nullopt, std::nullopt, updated_buffs);
        } catch (const std::exception& error) {
            OutputDebugStringA((std::string{"Aika NPC buff persistence failed: "} +
                error.what() + "\n").c_str());
            return true;
        }
        if (!replace_character(session, updated)) return false;
        for (const auto buff_id : accepted) {
            const auto extra_seconds = option == 0x23U || buff_id != 6499U
                ? 6000U : 0U;
            const auto end_time = now + extra_seconds +
                tables.skill_definitions[buff_id].duration;
            std::vector<std::byte> packet(24U);
            protocol::PacketHeader header{};
            header.size = static_cast<std::uint16_t>(packet.size());
            header.client_index = session.client_id;
            header.opcode = 0x016fU;
            const auto encoded = protocol::encode_header(header);
            std::copy(encoded.begin(), encoded.end(), packet.begin());
            write_u32(buff_id, packet, 12U);
            write_u32(static_cast<std::uint32_t>(end_time), packet, 16U);
            if (!send_to_visible(session, packet)) return false;
        }
        if (!refresh_buffs(session, tables)) return false;
        auto status = make_refresh_status_packet(updated, tables);
        if (!send_to_session(session, status)) return false;
        auto points = make_refresh_points_packet(updated);
        if (!send_to_session(session, points)) return false;
        auto hp_mp = make_current_hp_mp_packet(updated, session.client_id, tables);
        if (!send_to_session(session, hp_mp)) return false;
        if (option == 0x41U) {
            const auto money = make_refresh_money_packet(updated, session.account);
            std::vector<std::byte> packet{money.begin(), money.end()};
            if (!send_to_session(session, packet)) return false;
        }
        session.opened_npc = 0U;
        session.opened_npc_option = 0U;
        return true;
    }

    [[nodiscard]] bool repair_items(GameSession& session,
            const std::span<const std::byte> request,
            const data::GameTables& tables) {
        if (request.size() < 36U || !session.entered_world ||
            !session.selected_character.has_value()) return true;
        const auto repair_mode = read_u32(request, 12U);
        if (repair_mode > 1U) return true;
        if (session.opened_npc == 0U ||
            (session.opened_npc_option != 0x1fU &&
             session.opened_npc_option != 0x20U)) return true;
        database::CharacterRecord updated;
        {
            const std::lock_guard lock{clients_mutex_};
            const auto active = clients_.find(session.client_id);
            if (active == clients_.end() || active->second.get() != &session ||
                !session.selected_character.has_value()) return true;
            updated = *session.selected_character;
        }
        std::vector<database::CharacterItemPlacement> placements;
        long double total_cost{};
        const auto repair = [&tables, &updated, &placements, &total_cost](
                const std::uint8_t slot_type, const std::uint16_t slot) {
            database::CharacterItem* item{};
            if (slot_type == 0U && slot < updated.equipment.size())
                item = &updated.equipment[slot];
            else if (slot_type == 1U && slot < updated.inventory.size())
                item = &updated.inventory[slot];
            if (item == nullptr || item->item_id == 0U ||
                item->item_id >= tables.item_definitions.size() ||
                item->max == 0U || item->min >= item->max) return;
            const auto& definition = tables.item_definitions[item->item_id];
            long double rank_multiplier = 1.0L;
            if (definition.rank > 1U)
                rank_multiplier = static_cast<long double>(definition.rank - 1U);
            const auto lost_durability = item->max - item->min;
            total_cost += static_cast<long double>(definition.sell_price) * 0.00025L *
                static_cast<long double>(lost_durability) * rank_multiplier;
            item->min = item->max;
            placements.push_back({slot_type, slot, *item});
        };
        if (repair_mode == 0U) {
            for (std::uint16_t index = 0U; index < 10U; ++index) {
                const auto slot_type = std::to_integer<std::uint8_t>(request[26U + index]);
                const auto slot = std::to_integer<std::uint8_t>(request[16U + index]);
                if (slot_type == 255U) continue;
                repair(slot_type, slot);
            }
        } else {
            for (std::uint16_t slot = 0U; slot < 60U; ++slot)
                repair(1U, slot);
            for (std::uint16_t slot = 2U; slot <= 7U; ++slot)
                repair(0U, slot);
        }
        if (placements.empty()) return true;
        const auto rounded_cost = std::nearbyint(total_cost);
        if (!std::isfinite(static_cast<double>(rounded_cost)) || rounded_cost < 0.0L ||
            rounded_cost > static_cast<long double>(updated.gold) ||
            rounded_cost > static_cast<long double>(
                (std::numeric_limits<std::uint64_t>::max)())) {
            auto message = make_client_message_packet("Gold insuficiente para reparar.",
                session.client_id);
            return send_to_session(session, message);
        }
        const auto cost = static_cast<std::uint64_t>(rounded_cost);
        updated.gold -= cost;
        try {
            database::MysqlConnection database{database_config_};
            database.save_character_items(updated.id, updated.gold, placements);
        } catch (const std::exception& error) {
            OutputDebugStringA((std::string{"Aika equipment repair failed: "} +
                error.what() + "\n").c_str());
            return true;
        }
        if (!replace_character(session, updated)) return false;
        for (const auto& placement : placements) {
            auto refresh = make_refresh_item_packet(placement.slot_type,
                placement.slot, placement.item);
            if (!send_to_session(session, refresh)) return false;
        }
        const auto money = make_refresh_money_packet(updated, session.account);
        std::vector<std::byte> money_packet{money.begin(), money.end()};
        if (!send_to_session(session, money_packet)) return false;
        auto response = std::vector<std::byte>{request.begin(), request.end()};
        return send_to_session(session, response);
    }

    [[nodiscard]] bool refresh_player_spawn(GameSession& session,
            const data::GameTables& tables) {
        database::AccountRecord account;
        database::CharacterRecord character;
        std::vector<std::shared_ptr<GameSession>> visible;
        {
            const std::lock_guard lock{clients_mutex_};
            const auto active = clients_.find(session.client_id);
            if (active == clients_.end() || active->second.get() != &session ||
                !session.selected_character.has_value()) return false;
            account = session.account;
            character = *session.selected_character;
            for (const auto id : session.visible_players) {
                const auto recipient = clients_.find(id);
                if (recipient != clients_.end()) visible.push_back(recipient->second);
            }
        }
        auto self_spawn = make_create_mob_packet(account, character,
            session.client_id, tables);
        if (!send_to_session(session, self_spawn)) return false;
        for (const auto& recipient : visible) {
            auto spawn = make_create_mob_packet(account, character,
                session.client_id, tables);
            if (!send_to_session(*recipient, spawn)) return false;
        }
        return true;
    }

    [[nodiscard]] bool refresh_buffs(GameSession& session,
            const data::GameTables& tables) {
        database::CharacterRecord character;
        std::vector<std::shared_ptr<GameSession>> visible;
        {
            const std::lock_guard lock{clients_mutex_};
            const auto active = clients_.find(session.client_id);
            if (active == clients_.end() || active->second.get() != &session ||
                !session.selected_character.has_value()) return false;
            character = *session.selected_character;
            for (const auto id : session.visible_players) {
                const auto recipient = clients_.find(id);
                if (recipient != clients_.end()) visible.push_back(recipient->second);
            }
        }
        auto self_packet = make_refresh_buffs_packet(character, session.client_id, tables);
        if (!send_to_session(session, self_packet)) return false;
        for (const auto& recipient : visible) {
            auto update = make_refresh_buffs_packet(character, session.client_id, tables);
            if (!send_to_session(*recipient, update)) return false;
        }
        return true;
    }

    [[nodiscard]] bool send_to_visible(GameSession& session,
            const std::vector<std::byte>& packet, const bool include_self = true) {
        std::vector<std::shared_ptr<GameSession>> recipients;
        {
            const std::lock_guard lock{clients_mutex_};
            const auto active = clients_.find(session.client_id);
            if (active == clients_.end() || active->second.get() != &session)
                return false;
            if (include_self) recipients.push_back(active->second);
            for (const auto id : session.visible_players) {
                const auto recipient = clients_.find(id);
                if (recipient != clients_.end()) recipients.push_back(recipient->second);
            }
        }
        for (const auto& recipient : recipients) {
            auto copy = packet;
            if (!send_to_session(*recipient, copy)) return false;
        }
        return true;
    }

    [[nodiscard]] bool relay_player_action(GameSession& session,
            std::vector<std::byte>& request, const std::uint16_t opcode) {
        const auto minimum_size = opcode == update_action_opcode ? 20U : 16U;
        if (request.size() < minimum_size || !session.entered_world ||
            !session.selected_character.has_value() ||
            session.selected_character->current_hp == 0U) return true;
        const auto decoded = protocol::decode_header(request);
        if (!decoded || decoded.header.opcode != opcode ||
            decoded.header.size != request.size()) return true;
        if (opcode == update_action_opcode) {
            const auto action = read_u32(request, 12U);
            if (action == 40U || action == 65U) session.current_action = action;
        }
        auto relay_header = decoded.header;
        relay_header.client_index = session.client_id;
        const auto encoded = protocol::encode_header(relay_header);
        std::copy(encoded.begin(), encoded.end(), request.begin());
        return send_to_visible(session, request, false);
    }

    [[nodiscard]] bool teleport_player(GameSession& session, const float x,
            const float y, const data::GameTables& tables) {
        if (!session.entered_world || !session.selected_character.has_value() ||
            session.selected_character->current_hp == 0U ||
            !std::isfinite(x) || !std::isfinite(y) || x <= 0.0F || y <= 0.0F)
            return true;
        const auto character = *session.selected_character;
        std::vector<std::byte> teleport(32U);
        protocol::PacketHeader header{};
        header.size = static_cast<std::uint16_t>(teleport.size());
        header.client_index = session.client_id;
        header.opcode = movement_opcode;
        const auto encoded = protocol::encode_header(header);
        std::copy(encoded.begin(), encoded.end(), teleport.begin());
        write_f32(x, teleport, 12U);
        write_f32(y, teleport, 16U);
        teleport[26U] = std::byte{1U}; // Delphi MOVE_TELEPORT
        auto self_teleport = teleport;
        if (!send_to_session(session, self_teleport) ||
            !move(session, teleport, tables)) return false;
        save_transform(session, x, y, character.rotation);
        return true;
    }

    [[nodiscard]] bool attack_target(GameSession& session,
            const std::span<const std::byte> request,
            const data::GameTables& tables) {
        constexpr std::size_t attack_packet_size = 48U;
        constexpr auto basic_attack_delay = std::chrono::milliseconds{300};
        if (request.size() < attack_packet_size || !session.entered_world ||
            !session.selected_character.has_value()) return true;
        const auto target_id = read_u16(request, 12U);
        const auto animation = read_u16(request, 28U);
        const auto skill_id = read_u16(request, 30U);
        if (target_id < 3048U || target_id > 9147U) return true;

        const data::SkillDefinition* skill{};
        auto skill_mp_cost = 0U;
        if (skill_id != 0U) {
            if (skill_id >= tables.skill_definitions.size()) return true;
            skill = &tables.skill_definitions[skill_id];
            const auto& character = *session.selected_character;
            const bool learned = std::any_of(character.skills.begin(),
                character.skills.end(), [skill_id](const auto& placement) {
                    const auto base = static_cast<std::uint32_t>(placement[0]);
                    const auto level = static_cast<std::uint32_t>(placement[1]);
                    return level != 0U && skill_id >= base && skill_id < base + level &&
                        skill_id - base < 16U;
                });
            const auto job = character_job(character.class_info);
            const auto skill_job = skill->class_id <= 59U
                ? character_job(static_cast<std::uint16_t>(skill->class_id))
                : std::nullopt;
            const bool has_effects = std::any_of(skill->effects.begin(),
                skill->effects.end(), [](const auto effect) { return effect != 0; });
            if (!learned || skill->min_level > character.level ||
                skill->level > character.level ||
                !job.has_value() || (skill->class_id != 0U &&
                    (!skill_job.has_value() || *skill_job != *job)) ||
                skill->cast_time != 0U || skill->success_rate != 1U ||
                skill->range != 0U || skill->max_targets > 1U ||
                skill->buff_debuff != 0U || has_effects || skill->duration != 0U ||
                ((skill->class_id >= 61U && skill->class_id <= 84U) &&
                    skill->duration == 0U)) return true;
            skill_mp_cost = skill->mp_cost;
        }

        std::vector<std::shared_ptr<GameSession>> recipients;
        std::uint32_t current_hp{};
        std::uint32_t damage{};
        bool killed{};
        const data::MobSpawn* killed_spawn{};
        const data::MobAttributes* killed_attributes{};
        database::CharacterRecord attacker;
        const auto now = std::chrono::steady_clock::now();
        {
            const std::lock_guard lock{clients_mutex_};
            const auto active = clients_.find(session.client_id);
            if (active == clients_.end() || active->second.get() != &session ||
                !session.selected_character.has_value() ||
                session.selected_character->current_hp == 0U ||
                !session.visible_mobs.contains(target_id) ||
                now - session.last_basic_attack_at <= basic_attack_delay ||
                (skill != nullptr && session.last_skill_use_at.contains(skill_id) &&
                    now - session.last_skill_use_at.at(skill_id) <=
                        std::chrono::milliseconds{skill->cooldown}) ||
                session.selected_character->equipment[6U].item_id == 0U)
                return true;

            auto state = mob_states_.find(target_id);
            if (state == mob_states_.end() || state->second.dead ||
                state->second.current_hp == 0U) return true;
            const auto spawn = std::find_if(world_data_->mob_spawns.begin(),
                world_data_->mob_spawns.end(), [target_id](const auto& candidate) {
                    return candidate.client_id == target_id;
                });
            if (spawn == world_data_->mob_spawns.end() ||
                spawn->mob_template_id >= world_data_->mob_templates.size()) return true;
            const auto& mob_template = world_data_->mob_templates[spawn->mob_template_id];
            if (!mob_template.attributes.has_value() ||
                mob_template.attributes->is_service ||
                (mob_template.attributes->is_guard && session.account.nation == 0U) ||
                distance(session.selected_character->position_x,
                    session.selected_character->position_y,
                    state->second.position_x, state->second.position_y) > watch_distance ||
                (skill != nullptr && skill->range != 0U &&
                    distance(session.selected_character->position_x,
                        session.selected_character->position_y,
                        state->second.position_x, state->second.position_y) >
                            skill->range)) return true;

            attacker = *session.selected_character;
            if (skill != nullptr) {
                if (attacker.current_mp < skill_mp_cost) {
                    auto message = make_client_message_packet(
                        "Você não possui MP necessário para realizar a habilidade.",
                        session.client_id);
                    return send_to_session(session, message);
                }
                attacker.current_mp -= skill_mp_cost;
                try {
                    database::MysqlConnection database{database_config_};
                    database.save_character_items(attacker.id, attacker.gold, {}, {},
                        std::pair{attacker.current_hp, attacker.current_mp});
                } catch (const std::exception& error) {
                    OutputDebugStringA((std::string{"Aika skill MP persistence failed: "} +
                        error.what() + "\n").c_str());
                    return true;
                }
                session.selected_character->current_mp = attacker.current_mp;
                session.last_skill_use_at[skill_id] = now;
            }
            session.last_basic_attack_at = now;
            const auto attack_status = calculate_combat_status(attacker, tables);
            const bool physical = skill == nullptr ||
                character_job(attacker.class_info).value_or(4U) <= 3U;
            const auto attack_power = physical ? attack_status.physical_attack
                : attack_status.magical_attack;
            const auto defense = physical ? mob_template.attributes->physical_defense
                : mob_template.attributes->magical_defense;
            const auto base_damage = attack_power > (defense >> 3U)
                ? static_cast<std::uint32_t>(attack_power -
                    (defense >> 3U)) : 1U;
            static thread_local std::mt19937 random_engine{std::random_device{}()};
            const auto low = base_damage / 20U;
            const auto high = (std::max)(low, base_damage / 10U);
            const auto variance = std::uniform_int_distribution<std::uint32_t>{
                low, high}(random_engine);
            damage = base_damage + variance + 13U;
            if (skill != nullptr) {
                // Delphi AttackParse adds (skill damage + HabAtk) / 2.
                // HabAtk is not yet represented in the C++ character model.
                const auto skill_bonus = skill->damage / 2U;
                damage = static_cast<std::uint32_t>((std::min<std::uint64_t>)(
                    static_cast<std::uint64_t>(damage) + skill_bonus,
                    (std::numeric_limits<std::uint32_t>::max)()));
            }
            damage = (std::max)(damage, 1U);
            killed = damage >= state->second.current_hp;
            current_hp = killed ? 0U : state->second.current_hp - damage;
            state->second.current_hp = current_hp;
            if (killed) {
                state->second.dead = true;
                state->second.aggro_target = 0U;
                state->second.next_attack_at = {};
                state->second.respawn_at = now + std::chrono::seconds{
                    (std::max)(mob_template.attributes->respawn_seconds, 1U)};
                killed_spawn = &*spawn;
                killed_attributes = &*mob_template.attributes;
            } else {
                state->second.aggro_target = session.client_id;
                state->second.next_attack_at = now + std::chrono::seconds{1};
                state->second.returning = false;
            }
            session.last_basic_attack_at = now;
            for (const auto& [id, recipient] : clients_) {
                if (id == session.client_id ||
                    recipient->visible_mobs.contains(target_id))
                    recipients.push_back(recipient);
            }
            if (killed) {
                for (auto& [id, recipient] : clients_) {
                    (void)id;
                    recipient->visible_mobs.erase(target_id);
                }
            }
        }

        std::vector<std::byte> response(84U);
        protocol::PacketHeader header{};
        header.size = static_cast<std::uint16_t>(response.size());
        header.client_index = session.client_id;
        header.opcode = 0x0102U;
        const auto encoded = protocol::encode_header(header);
        std::copy(encoded.begin(), encoded.end(), response.begin());
        write_u32(skill_id, response, 12U);
        write_f32(attacker.position_x, response, 16U);
        write_f32(attacker.position_y, response, 20U);
        write_u16(session.client_id, response, 28U);
        response[31U] = static_cast<std::byte>((skill != nullptr
            ? skill->self_animation : animation) & 0xffU);
        write_u32(attacker.current_hp, response, 44U);
        write_u16(target_id, response, 56U);
        response[58U] = std::byte{0U}; // TDamageType.Normal
        response[59U] = static_cast<std::byte>(skill != nullptr
            ? skill->target_animation : (killed ? 30U : 0U));
        write_u64(damage, response, 60U);
        write_u32(current_hp, response, 72U);
        for (const auto& recipient : recipients) {
            auto packet = response;
            if (!send_to_session(*recipient, packet)) return false;
        }
        if (skill != nullptr) {
            auto hp_mp = make_current_hp_mp_packet(attacker, session.client_id, tables);
            if (!send_to_session(session, hp_mp)) return false;
        }
        if (killed && killed_spawn != nullptr && killed_attributes != nullptr)
            return award_mob_kill(session, *killed_spawn, *killed_attributes, tables);
        return true;
    }

    [[nodiscard]] bool award_mob_kill(GameSession& session,
            const data::MobSpawn& spawn,
            const data::MobAttributes& mob,
            const data::GameTables& tables) {
        database::CharacterRecord updated;
        {
            const std::lock_guard lock{clients_mutex_};
            const auto active = clients_.find(session.client_id);
            if (active == clients_.end() || active->second.get() != &session ||
                !session.selected_character.has_value()) return true;
            updated = *session.selected_character;
        }
        const auto empty_slot = first_empty_inventory_slot(updated.inventory);
        const auto original_gold = updated.gold;
        const auto original_experience = updated.experience;
        std::uint64_t mob_experience = mob.experience;
        const auto level_difference = static_cast<std::int32_t>(mob.level) -
            static_cast<std::int32_t>(updated.level);
        if (level_difference <= -8) mob_experience = 1U;
        else if (level_difference <= -3)
            mob_experience = static_cast<std::uint64_t>(std::nearbyint(
                static_cast<double>(mob_experience) * 0.5));
        else if (level_difference >= 6)
            mob_experience = static_cast<std::uint64_t>(std::nearbyint(
                static_cast<double>(mob_experience) * 0.2));
        else if (level_difference >= 3)
            mob_experience = static_cast<std::uint64_t>(std::nearbyint(
                static_cast<double>(mob_experience) * 1.5));
        const auto premium_rate = character_has_effect(updated, tables, 387U) ? 4U :
            character_has_effect(updated, tables, 278U) ? 2U : 1U;
        if (mob_experience > (std::numeric_limits<std::uint64_t>::max)() /
                premium_rate)
            mob_experience = (std::numeric_limits<std::uint64_t>::max)();
        else mob_experience *= premium_rate;
        if (experience_multiplier_ != 0U && mob_experience >
                (std::numeric_limits<std::uint64_t>::max)() / experience_multiplier_)
            mob_experience = (std::numeric_limits<std::uint64_t>::max)();
        else mob_experience *= experience_multiplier_;

        if (mob_experience > (std::numeric_limits<std::uint64_t>::max)() -
                updated.experience)
            updated.experience = (std::numeric_limits<std::uint64_t>::max)();
        else updated.experience += mob_experience;
        std::vector<std::pair<std::uint16_t, std::uint16_t>> event_rewards;
        const auto level_cap = static_cast<std::uint16_t>((std::min<std::size_t>)(
            90U, tables.experience_table.empty() ? 0U :
                tables.experience_table.size() - 1U));
        bool leveled_up = false;
        while (updated.level < level_cap &&
            updated.experience > tables.experience_table[updated.level]) {
            apply_character_level_award(updated, 1U, event_rewards);
            leveled_up = true;
        }
        if (updated.level == level_cap && level_cap < tables.experience_table.size() &&
            updated.experience > tables.experience_table[level_cap])
            updated.experience = tables.experience_table[level_cap];
        if (leveled_up) {
            const auto [max_hp, max_mp] = estimate_max_hp_mp(updated, tables);
            updated.current_hp = max_hp;
            updated.current_mp = max_mp;
        }

        std::vector<database::CharacterItemPlacement> item_updates;
        static thread_local std::mt19937 random_engine{std::random_device{}()};
        auto drop_tax = std::uniform_int_distribution<int>{1, 100}(random_engine);
        if (++session.mob_drop_count >= 4U) {
            drop_tax += 50;
            session.mob_drop_count = 0U;
        }
        if (drop_tax > 70 && empty_slot.has_value()) {
            auto item_tax = std::uniform_int_distribution<int>{1, 100}(random_engine);
            std::uint8_t category = item_tax == 1 ? 4U :
                item_tax <= 13 ? 3U : item_tax <= 33 ? 2U : 1U;
            static constexpr std::array<std::string_view, 13U> drop_files{
                "Monsters_0_20_DropList.csv", "Monsters_21_40_DropList.csv",
                "Monsters_41_60_DropList.csv", "Monsters_61_80_DropList.csv",
                "Monsters_81_99_DropList.csv", "Planta_DropList.csv",
                "CroshuAzul_DropList.csv", "CroshuVerm_DropList.csv",
                "Buto_DropList.csv", "Penza_DropList.csv", "Verit_DropList.csv",
                "DropAdicional01_DropList.csv", "DropAdicional02_DropList.csv"};
            if (mob.drop_index < drop_files.size()) {
                const auto source = drop_files[mob.drop_index];
                std::vector<std::uint16_t> items;
                for (std::uint8_t selected = category; selected <= 4U; ++selected) {
                    items.clear();
                    for (const auto& entry : tables.drop_entries)
                        if (entry.source_file == source && entry.category == selected &&
                            entry.item_index > 0 &&
                            static_cast<std::size_t>(entry.item_index) <
                                tables.item_definitions.size())
                            items.push_back(static_cast<std::uint16_t>(entry.item_index));
                    if (!items.empty()) break;
                    if (selected == 4U) {
                        for (const auto& entry : tables.drop_entries)
                            if (entry.source_file == source && entry.category == 1 &&
                                entry.item_index > 0 &&
                                static_cast<std::size_t>(entry.item_index) <
                                    tables.item_definitions.size())
                                items.push_back(static_cast<std::uint16_t>(entry.item_index));
                    }
                    if (!items.empty()) break;
                }
                if (!items.empty()) {
                    const auto selected = std::uniform_int_distribution<std::size_t>{
                        0U, items.size() - 1U}(random_engine);
                    const auto item_id = items[selected];
                    const auto& definition = tables.item_definitions[item_id];
                    database::CharacterItem item{};
                    item.item_id = item_id;
                    item.app = item_id;
                    item.refine = 1U;
                    item.min = definition.durability;
                    item.max = definition.durability;
                    auto drop_slot = *empty_slot;
                    if (definition.can_group != 0U) {
                        for (std::uint16_t slot = 0U; slot < 64U; ++slot) {
                            const auto& candidate = updated.inventory[slot];
                            if (candidate.item_id == item_id && candidate.refine < 1000U) {
                                drop_slot = slot;
                                break;
                            }
                        }
                    }
                    auto& destination = updated.inventory[drop_slot];
                    if (destination.item_id == item_id) {
                        ++destination.refine;
                    } else {
                        destination = item;
                    }
                    item_updates.push_back({1U, drop_slot, destination});
                }
            }
        }

        const bool progression_changed = updated.experience != original_experience ||
            leveled_up || updated.gold != original_gold;
        const std::optional<database::CharacterProgression> progression =
            progression_changed ? std::optional<database::CharacterProgression>{
                database::CharacterProgression{updated.class_info, updated.level,
                    updated.skill_points, updated.attributes, updated.experience,
                    updated.gold, updated.current_hp, updated.current_mp}}
                : std::nullopt;
        try {
            database::MysqlConnection database{database_config_};
            database.save_character_items(updated.id, updated.gold, item_updates, {},
                std::nullopt, std::nullopt, std::nullopt, progression, event_rewards);
        } catch (const std::exception& error) {
            OutputDebugStringA((std::string{"Aika mob reward persistence failed: "} +
                error.what() + "\n").c_str());
            return true;
        }
        {
            const std::lock_guard lock{clients_mutex_};
            const auto active = clients_.find(session.client_id);
            if (active == clients_.end() || active->second.get() != &session ||
                !session.selected_character.has_value()) return false;
            *session.selected_character = updated;
        }

        if (!item_updates.empty()) {
            auto refresh = make_refresh_item_packet(1U, item_updates.front().slot,
                updated.inventory[item_updates.front().slot]);
            if (!send_to_session(session, refresh)) return false;
        }
        if (progression_changed) {
            if (updated.experience != original_experience) {
                auto level = make_refresh_level_packet(updated, session.client_id);
                const auto message_text = "Adquiriu " +
                    std::to_string(mob_experience) + " exp.";
                auto message = make_client_message_packet(message_text,
                    session.client_id, 0U);
                if (!send_to_session(session, level) ||
                    !send_to_session(session, message)) return false;
            }
            if (leveled_up) {
                // TPlayer::AddLevel sends HP/MP, level, points, then effect
                // $0117. It does not send $010A here; refreshing that status
                // during level-up makes this client lose its movement speed.
                auto hp_mp = make_current_hp_mp_packet(updated, session.client_id,
                    tables, true);
                auto level = make_refresh_level_packet(updated, session.client_id);
                auto points = make_refresh_points_packet(updated);
                auto effect = make_character_effect_packet(session.client_id, 1U);
                if (!send_to_session(session, hp_mp) ||
                    !send_to_session(session, level) ||
                    !send_to_session(session, points) ||
                    !send_to_session(session, effect)) return false;
            }
            if (updated.gold != original_gold) {
                const auto money = make_refresh_money_packet(updated, session.account);
                std::vector<std::byte> packet{money.begin(), money.end()};
                if (!send_to_session(session, packet)) return false;
            }
        }
        (void)spawn;
        return true;
    }

    [[nodiscard]] bool revive_player(GameSession& session,
            const data::GameTables& tables) {
        database::CharacterRecord updated;
        {
            const std::lock_guard lock{clients_mutex_};
            const auto active = clients_.find(session.client_id);
            if (active == clients_.end() || active->second.get() != &session ||
                !session.entered_world || !session.selected_character.has_value())
                return true;
            updated = *session.selected_character;
        }

        const auto [max_hp, max_mp] = estimate_max_hp_mp(updated, tables);
        updated.current_hp = max_hp / 10U;
        updated.current_mp = max_mp / 10U;
        const auto valid_saved_position = [](const float x, const float y) {
            return std::isfinite(x) && std::isfinite(y) && x > 0.0F && y > 0.0F;
        };
        const float destination_x = valid_saved_position(updated.saved_position_x,
            updated.saved_position_y) ? updated.saved_position_x : 3450.0F;
        const float destination_y = valid_saved_position(updated.saved_position_x,
            updated.saved_position_y) ? updated.saved_position_y : 690.0F;

        for (auto& buff : updated.buffs) {
            const auto skill_id = static_cast<std::size_t>(buff[0]);
            if (skill_id == 0U || skill_id >= tables.skill_definitions.size()) continue;
            const auto buff_type = tables.skill_definitions[skill_id].buff_debuff;
            if (buff_type == 3U || buff_type == 4U) buff = {};
        }

        try {
            database::MysqlConnection database{database_config_};
            database.save_character_items(updated.id, updated.gold, {}, {},
                std::pair{updated.current_hp, updated.current_mp}, std::nullopt,
                updated.buffs);
        } catch (const std::exception& error) {
            OutputDebugStringA((std::string{"Aika revive save failed: "} +
                error.what() + "\n").c_str());
            return true;
        }

        {
            const std::lock_guard lock{clients_mutex_};
            const auto active = clients_.find(session.client_id);
            if (active == clients_.end() || active->second.get() != &session ||
                !session.selected_character.has_value()) return false;
            *session.selected_character = updated;
            session.current_action = 0U;
            session.opened_npc = 0U;
            session.opened_npc_option = 0U;
        }

        std::vector<std::byte> teleport(32U);
        protocol::PacketHeader header{};
        header.size = static_cast<std::uint16_t>(teleport.size());
        header.client_index = session.client_id;
        header.opcode = movement_opcode;
        const auto encoded = protocol::encode_header(header);
        std::copy(encoded.begin(), encoded.end(), teleport.begin());
        write_f32(destination_x, teleport, 12U);
        write_f32(destination_y, teleport, 16U);
        teleport[26U] = std::byte{1U}; // Delphi MOVE_TELEPORT
        auto self_teleport = teleport;
        if (!send_to_session(session, self_teleport)) return false;
        if (!move(session, teleport, tables)) return false;
        save_transform(session, destination_x, destination_y, updated.rotation);

        auto status = make_refresh_status_packet(updated, tables);
        auto points = make_refresh_points_packet(updated);
        auto hp_mp = make_current_hp_mp_packet(updated, session.client_id, tables);
        if (!send_to_visible(session, status) || !send_to_visible(session, points) ||
            !send_to_visible(session, hp_mp) || !refresh_buffs(session, tables))
            return false;
        return true;
    }

    [[nodiscard]] bool refresh_equipment_status(GameSession& session,
            const data::GameTables& tables) {
        database::CharacterRecord character;
        {
            const std::lock_guard lock{clients_mutex_};
            const auto active = clients_.find(session.client_id);
            if (active == clients_.end() || active->second.get() != &session ||
                !session.selected_character.has_value()) return false;
            character = *session.selected_character;
        }
        auto status = make_refresh_status_packet(character, tables);
        auto points = make_refresh_points_packet(character);
        auto hp_mp = make_current_hp_mp_packet(character, session.client_id, tables);
        return send_to_session(session, status) && send_to_session(session, points) &&
            send_to_session(session, hp_mp);
    }

    [[nodiscard]] bool replace_character(GameSession& session,
            database::CharacterRecord character) {
        const std::lock_guard lock{clients_mutex_};
        const auto active = clients_.find(session.client_id);
        if (active == clients_.end() || active->second.get() != &session ||
            !session.selected_character.has_value()) return false;
        *session.selected_character = std::move(character);
        return true;
    }

    [[nodiscard]] std::optional<std::pair<database::CharacterItem,
            database::CharacterItem>> move_character_items(GameSession& session,
            const std::uint16_t source_type, const std::uint16_t source_slot,
            const std::uint16_t destination_type, const std::uint16_t destination_slot) {
        const std::lock_guard lock{clients_mutex_};
        const auto active = clients_.find(session.client_id);
        if (active == clients_.end() || active->second.get() != &session ||
            !session.selected_character.has_value()) return std::nullopt;
        auto& character = *session.selected_character;
        auto& source = source_type == 1U
            ? character.inventory[source_slot] : character.equipment[source_slot];
        auto& destination = destination_type == 1U
            ? character.inventory[destination_slot] : character.equipment[destination_slot];
        std::swap(source, destination);
        return std::pair{source, destination};
    }

    [[nodiscard]] std::optional<std::pair<database::CharacterItem,
            database::CharacterItem>> merge_character_stacks(GameSession& session,
            const std::uint16_t source_slot, const std::uint16_t destination_slot,
            const std::uint16_t source_quantity,
            const std::uint16_t destination_quantity,
            const std::uint16_t new_source_quantity,
            const std::uint16_t new_destination_quantity) {
        const std::lock_guard lock{clients_mutex_};
        const auto active = clients_.find(session.client_id);
        if (active == clients_.end() || active->second.get() != &session ||
            !session.selected_character.has_value()) return std::nullopt;
        auto& inventory = session.selected_character->inventory;
        auto& source = inventory[source_slot];
        auto& destination = inventory[destination_slot];
        if (source.refine != source_quantity || destination.refine != destination_quantity)
            return std::nullopt;
        source.refine = new_source_quantity;
        if (new_destination_quantity == 0U) destination = {};
        else destination.refine = new_destination_quantity;
        return std::pair{source, destination};
    }

    [[nodiscard]] std::optional<std::uint32_t> change_item_bar(GameSession& session,
            const std::uint32_t destination_slot, const std::uint32_t source_type,
            const std::uint32_t source_index) {
        if (destination_slot >= 32U) return std::nullopt;
        std::uint32_t character_id{};
        std::uint32_t bar_item{};
        {
            const std::lock_guard lock{clients_mutex_};
            const auto active = clients_.find(session.client_id);
            if (active == clients_.end() || active->second.get() != &session ||
                !session.selected_character.has_value()) return std::nullopt;
            const auto& character = *session.selected_character;
            character_id = character.id;
            if (source_type == 0U) {
                bar_item = 0U;
            } else if (source_type == 2U) {
                if (source_index > (0xffffffffU - 2U) / 16U) return std::nullopt;
                bar_item = source_index * 16U + 2U;
            } else if (source_type == 6U) {
                const auto found = std::find_if(character.inventory.begin(),
                    character.inventory.begin() + 60, [&character, source_index](
                        const auto& item) {
                        const auto slot = static_cast<std::uint16_t>(
                            &item - character.inventory.data());
                        return is_inventory_slot_unlocked(character.inventory, slot) &&
                            item.item_id == source_index;
                    });
                if (found == character.inventory.begin() + 60) return std::nullopt;
                bar_item = source_index;
            } else {
                return std::nullopt; // Pran bars require the separately loaded Pran state.
            }
        }

        try {
            database::MysqlConnection database{database_config_};
            database.save_character_item_bar_slot(character_id,
                static_cast<std::uint8_t>(destination_slot), bar_item);
        } catch (...) {
            return std::nullopt;
        }
        {
            const std::lock_guard lock{clients_mutex_};
            const auto active = clients_.find(session.client_id);
            if (active == clients_.end() || active->second.get() != &session ||
                !session.selected_character.has_value()) return std::nullopt;
            session.selected_character->item_bar[destination_slot] = bar_item;
        }
        return bar_item;
    }

    [[nodiscard]] std::optional<database::CharacterRecord> allocate_status_points(
            GameSession& session, const std::uint32_t status_index,
            const std::uint32_t amount) {
        if (status_index >= 5U || amount > 65535U) return std::nullopt;
        database::CharacterRecord updated;
        {
            const std::lock_guard lock{clients_mutex_};
            const auto active = clients_.find(session.client_id);
            if (active == clients_.end() || active->second.get() != &session ||
                !session.selected_character.has_value()) return std::nullopt;
            updated = *session.selected_character;
        }
        auto& attributes = updated.attributes;
        if (amount > attributes[5U] ||
            static_cast<std::uint32_t>(attributes[status_index]) + amount > 65535U)
            return std::nullopt;
        attributes[status_index] = static_cast<std::uint16_t>(
            attributes[status_index] + amount);
        attributes[5U] = static_cast<std::uint16_t>(attributes[5U] - amount);
        try {
            database::MysqlConnection database{database_config_};
            database.save_character_attributes(updated.id, attributes);
        } catch (...) {
            return std::nullopt;
        }
        {
            const std::lock_guard lock{clients_mutex_};
            const auto active = clients_.find(session.client_id);
            if (active == clients_.end() || active->second.get() != &session ||
                !session.selected_character.has_value()) return std::nullopt;
            session.selected_character->attributes = attributes;
            updated = *session.selected_character;
        }
        return updated;
    }

    [[nodiscard]] bool move(GameSession& session, std::vector<std::byte>& request,
            const data::GameTables& tables) {
        if (request.size() < 32U) return false;
        const auto x = read_f32(request, 12U);
        const auto y = read_f32(request, 16U);
        if (!std::isfinite(x) || !std::isfinite(y)) return false;

        std::vector<std::shared_ptr<GameSession>> moving_to;
        std::vector<std::pair<std::shared_ptr<GameSession>, database::CharacterRecord>> entering;
        std::vector<std::shared_ptr<GameSession>> leaving;
        std::vector<const data::MobSpawn*> mobs_entering;
        std::vector<const data::NpcDefinition*> npcs_entering;
        std::vector<std::uint32_t> mobs_leaving;
        database::CharacterRecord character_snapshot;
        bool persist_transform = false;
        std::uint32_t rotation{};
        {
            const std::lock_guard lock{clients_mutex_};
            const auto self = clients_.find(session.client_id);
            if (self == clients_.end() || self->second.get() != &session ||
                !session.selected_character.has_value()) return false;
            auto& character = *session.selected_character;
            if (character.current_hp == 0U) return true;
            character.position_x = x;
            character.position_y = y;
            session.current_action = 0U;
            character_snapshot = character;
            const auto now = std::chrono::steady_clock::now();
            if (now - session.last_saved_at >= save_interval) {
                session.last_saved_at = now;
                persist_transform = true;
                rotation = character.rotation;
            }

            std::unordered_set<std::uint16_t> next_visible;
            for (const auto& [id, other] : clients_) {
                if (id == session.client_id || !other->selected_character.has_value()) continue;
                const auto& other_character = *other->selected_character;
                const bool in_range = distance(x, y, other_character.position_x,
                    other_character.position_y) <= watch_distance;
                const bool was_visible = session.visible_players.contains(id);
                if (in_range) {
                    next_visible.insert(id);
                    if (was_visible) moving_to.push_back(other);
                    else {
                        entering.emplace_back(other, other_character);
                        other->visible_players.insert(session.client_id);
                    }
                } else if (was_visible) {
                    leaving.push_back(other);
                    other->visible_players.erase(session.client_id);
                }
            }
            session.visible_players = std::move(next_visible);

            std::unordered_set<std::uint32_t> next_visible_mobs;
            for (const auto& spawn : world_data_->mob_spawns) {
                if (spawn.client_id > 65535U ||
                    spawn.mob_template_id >= world_data_->mob_templates.size()) continue;
                const auto& mob_template = world_data_->mob_templates[spawn.mob_template_id];
                if (!mob_template.attributes.has_value() ||
                    !mob_template.attributes->active_to_spawn) continue;
                auto state = mob_states_.find(spawn.client_id);
                if (state == mob_states_.end()) continue;
                if (state->second.dead && state->second.respawn_at <= now) {
                    state->second.current_hp = state->second.maximum_hp;
                    state->second.dead = false;
                    state->second.aggro_target = 0U;
                    state->second.next_attack_at = {};
                    state->second.position_x = spawn.initial_x;
                    state->second.position_y = spawn.initial_y;
                    state->second.returning = false;
                    state->second.next_move_at = {};
                    state->second.patrolling_to_destination = true;
                    state->second.next_patrol_at = now +
                        std::chrono::seconds{spawn.initial_move_wait};
                }
                if (state->second.dead || state->second.current_hp == 0U ||
                    state->second.position_x < 50.0F ||
                    state->second.position_y < 50.0F ||
                    distance(x, y, state->second.position_x,
                        state->second.position_y) > watch_distance) continue;
                next_visible_mobs.insert(spawn.client_id);
                if (!session.visible_mobs.contains(spawn.client_id))
                    mobs_entering.push_back(&spawn);
            }
            for (const auto& npc : world_data_->npcs) {
                if (npc.id > 65535U || npc.position_x <= 0.0F || npc.position_y <= 0.0F ||
                    distance(x, y, npc.position_x, npc.position_y) > watch_distance)
                    continue;
                next_visible_mobs.insert(npc.id);
                if (!session.visible_mobs.contains(npc.id))
                    npcs_entering.push_back(&npc);
            }
            for (const auto id : session.visible_mobs)
                if (!next_visible_mobs.contains(id)) mobs_leaving.push_back(id);
            session.visible_mobs = std::move(next_visible_mobs);
        }

        auto decoded = protocol::decode_header(request);
        if (!decoded) return false;
        decoded.header.client_index = session.client_id;
        const auto encoded = protocol::encode_header(decoded.header);
        std::copy(encoded.begin(), encoded.end(), request.begin());
        for (const auto& [other, other_character] : entering) {
            auto to_mover = make_create_mob_packet(other->account,
                other_character, other->client_id, tables);
            if (!send_to_session(session, to_mover)) return false;
            auto to_other = make_create_mob_packet(session.account,
                character_snapshot, session.client_id, tables);
            if (!send_to_session(*other, to_other)) return false;
        }
        for (const auto& other : leaving) {
            const auto remove_other = make_remove_mob_packet(other->client_id);
            std::vector<std::byte> to_mover(remove_other.begin(), remove_other.end());
            const auto remove_mover = make_remove_mob_packet(session.client_id);
            std::vector<std::byte> to_other(remove_mover.begin(), remove_mover.end());
            if (!send_to_session(session, to_mover) || !send_to_session(*other, to_other))
                return false;
        }
        for (const auto& other : moving_to) {
            auto movement = request;
            if (!send_to_session(*other, movement)) return false;
        }
        for (const auto* spawn : mobs_entering) {
            const auto& mob_template = world_data_->mob_templates[spawn->mob_template_id];
            const auto current_hp = visible_mob_hp(spawn->client_id);
            if (current_hp == 0U) continue;
            const auto current_spawn = current_mob_spawn(*spawn);
            auto packet = make_world_mob_packet(current_spawn, mob_template,
                current_hp, session.account.nation != 0U);
            if (!packet.empty() && !send_to_session(session, packet)) return false;
        }
        for (const auto* npc : npcs_entering) {
            auto packet = make_npc_spawn_packet(*npc);
            if (!packet.empty() && !send_to_session(session, packet)) return false;
        }
        for (const auto mob_id : mobs_leaving) {
            const auto remove_mob = make_remove_mob_packet(
                static_cast<std::uint16_t>(mob_id));
            std::vector<std::byte> packet(remove_mob.begin(), remove_mob.end());
            if (!send_to_session(session, packet)) return false;
        }

        if (persist_transform) save_transform(session, x, y, rotation);
        return true;
    }

    [[nodiscard]] bool update_rotation(GameSession& session,
            std::vector<std::byte>& request) {
        if (request.size() < 16U) return false;
        const auto rotation = read_u32(request, 12U);
        std::vector<std::shared_ptr<GameSession>> visible;
        bool persist_transform = false;
        float x{};
        float y{};
        {
            const std::lock_guard lock{clients_mutex_};
            const auto self = clients_.find(session.client_id);
            if (self == clients_.end() || self->second.get() != &session ||
                !session.selected_character.has_value()) return false;
            session.selected_character->rotation = rotation;
            x = session.selected_character->position_x;
            y = session.selected_character->position_y;
            const auto now = std::chrono::steady_clock::now();
            if (now - session.last_saved_at >= save_interval) {
                session.last_saved_at = now;
                persist_transform = true;
            }
            for (const auto id : session.visible_players) {
                const auto other = clients_.find(id);
                if (other != clients_.end()) visible.push_back(other->second);
            }
        }
        auto decoded = protocol::decode_header(request);
        if (!decoded) return false;
        decoded.header.client_index = session.client_id;
        const auto encoded = protocol::encode_header(decoded.header);
        std::copy(encoded.begin(), encoded.end(), request.begin());
        for (const auto& other : visible) {
            auto update = request;
            if (!send_to_session(*other, update)) return false;
        }
        if (persist_transform) save_transform(session, x, y, rotation);
        return true;
    }

    [[nodiscard]] bool chat(GameSession& session, std::vector<std::byte>& request) {
        if (request.size() < 168U) return false;
        const auto chat_type = read_u16(request, 12U);
        const auto text = fixed_bytes(request, 40U, 128U);
        if (chat_type == 0U && text == "`ping") {
            session.ping_command_at = std::chrono::steady_clock::now();
            session.has_ping_command = true;
            const auto response = make_signal_packet(session.client_id,
                ping_reply_opcode, 0U);
            std::vector<std::byte> packet(response.begin(), response.end());
            return send_to_session(session, packet);
        }

        if (chat_type == 1U) {
            const auto recipient_name = fixed_string(request, 24U, 16U);
            std::shared_ptr<GameSession> recipient;
            {
                const std::lock_guard lock{clients_mutex_};
                for (const auto& [id, other] : clients_) {
                    (void)id;
                    if (other->selected_character.has_value() &&
                        fixed_string(std::as_bytes(std::span{
                            other->selected_character->name.data(),
                            other->selected_character->name.size()}), 0U,
                            other->selected_character->name.size()) == recipient_name) {
                        recipient = other;
                        break;
                    }
                }
            }
            if (!recipient) {
                auto message = make_client_message_packet(
                    "Personagem nao encontrado.", session.client_id);
                return send_to_session(session, message);
            }

            auto echo = request;
            if (!send_to_session(session, echo)) return false;
            auto to_recipient = request;
            const auto sender_name = session.selected_character.has_value()
                ? session.selected_character->name : std::string{};
            std::fill(to_recipient.begin() + 24, to_recipient.begin() + 40,
                std::byte{});
            std::copy_n(reinterpret_cast<const std::byte*>(sender_name.data()),
                std::min<std::size_t>(sender_name.size(), 16U),
                to_recipient.begin() + 24);
            return send_to_session(*recipient, to_recipient);
        }

        if (chat_type == 0U || chat_type == 4U) {
            std::vector<std::shared_ptr<GameSession>> recipients;
            bool shout_rate_limited = false;
            {
                const std::lock_guard lock{clients_mutex_};
                if (!session.selected_character.has_value()) return false;
                const auto self = clients_.find(session.client_id);
                if (self == clients_.end() || self->second.get() != &session) return false;
                if (chat_type == 4U) {
                    const auto now = std::chrono::steady_clock::now();
                    if (session.has_shouted && now - session.last_shout_at <
                            std::chrono::seconds{5}) {
                        shout_rate_limited = true;
                    } else {
                        session.has_shouted = true;
                        session.last_shout_at = now;
                        const auto nation = session.account.nation;
                        for (const auto& [id, other] : clients_) {
                            (void)id;
                            if (!other->selected_character.has_value()) continue;
                            if (nation == 0U || other->account.nation == 0U ||
                                other->account.nation == nation)
                                recipients.push_back(other);
                        }
                    }
                } else {
                    recipients.push_back(self->second);
                    for (const auto id : session.visible_players) {
                        const auto other = clients_.find(id);
                        if (other != clients_.end()) recipients.push_back(other->second);
                    }
                }
            }
            if (shout_rate_limited) {
                auto message = make_client_message_packet(
                    "Voce nao pode floodar o grito.", session.client_id);
                return send_to_session(session, message);
            }
            for (const auto& recipient : recipients) {
                auto packet = request;
                if (!send_to_session(*recipient, packet)) return false;
            }
            return true;
        }

        // Party, guild, ally, nation-role, and megaphone chat still need their
        // corresponding party/guild/role/inventory repositories.
        return true;
    }

    [[nodiscard]] bool request_server_time(GameSession& session) const {
        auto message = make_client_message_packet(local_datetime_string(),
            session.client_id);
        return send_to_session(session, message);
    }

    [[nodiscard]] bool request_server_ping(GameSession& session) const {
        std::int64_t milliseconds = 0;
        if (session.has_ping_command) {
            milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - session.ping_command_at).count();
        }
        auto message = make_client_message_packet(
            std::to_string(milliseconds) + " ms.", session.client_id);
        return send_to_session(session, message);
    }

    void leave(GameSession& session) noexcept {
        std::vector<std::shared_ptr<GameSession>> visible;
        std::uint32_t character_id{};
        float final_x{};
        float final_y{};
        std::uint32_t final_rotation{};
        bool save_transform = false;
        {
            const std::lock_guard lock{clients_mutex_};
            const auto self = clients_.find(session.client_id);
            if (self == clients_.end() || self->second.get() != &session) return;
            for (const auto id : session.visible_players) {
                const auto other = clients_.find(id);
                if (other == clients_.end()) continue;
                other->second->visible_players.erase(session.client_id);
                visible.push_back(other->second);
            }
            if (session.selected_character.has_value()) {
                const auto& character = *session.selected_character;
                character_id = character.id;
                final_x = static_cast<float>(std::nearbyint(character.position_x));
                final_y = static_cast<float>(std::nearbyint(character.position_y));
                final_rotation = character.rotation;
                save_transform = session.entered_world;
            }
            session.visible_players.clear();
            session.visible_mobs.clear();
            clients_.erase(self);
            session.entered_world = false;
        }
        if (save_transform) {
            try {
                database::MysqlConnection database{database_config_};
                database.save_character_position(character_id, final_x, final_y);
                database.save_character_rotation(character_id, final_rotation);
            } catch (const std::exception& error) {
                OutputDebugStringA((std::string{"Aika final character save failed: "} +
                    error.what() + "\n").c_str());
            }
        }
        const auto remove = make_remove_mob_packet(session.client_id);
        for (const auto& other : visible) {
            std::vector<std::byte> packet(remove.begin(), remove.end());
            try { (void)send_to_session(*other, packet); } catch (...) {}
        }
    }

private:
    static constexpr float watch_distance = 50.0F;
    static constexpr std::chrono::seconds save_interval{10};

    [[nodiscard]] static float read_f32(const std::span<const std::byte> bytes,
            const std::size_t offset) noexcept {
        return std::bit_cast<float>(read_u32(bytes, offset));
    }

    [[nodiscard]] static float distance(const float x1, const float y1,
            const float x2, const float y2) noexcept {
        return std::hypot(x1 - x2, y1 - y2);
    }

    void save_transform(const GameSession& session, const float x, const float y,
            const std::uint32_t rotation) const noexcept {
        if (!session.selected_character.has_value()) return;
        try {
            database::MysqlConnection database{database_config_};
            database.save_character_position(session.selected_character->id,
                static_cast<float>(std::nearbyint(x)),
                static_cast<float>(std::nearbyint(y)));
            database.save_character_rotation(session.selected_character->id, rotation);
        } catch (const std::exception& error) {
            OutputDebugStringA((std::string{"Aika character save failed: "} +
                error.what() + "\n").c_str());
        }
    }

    config::DatabaseConfig database_config_;
    const data::WorldData* world_data_{};
    std::uint16_t experience_multiplier_{1U};
    std::mutex clients_mutex_;
    std::unordered_map<std::uint16_t, std::shared_ptr<GameSession>> clients_;
    std::unordered_map<std::uint32_t, MobRuntimeState> mob_states_;
    std::chrono::steady_clock::time_point last_mob_tick_{};
    std::chrono::steady_clock::time_point last_mob_ai_tick_{};
};

class AccountPresence final {
public:
    explicit AccountPresence(config::DatabaseConfig config)
        : config_{std::move(config)} {}
    AccountPresence(const AccountPresence&) = delete;
    AccountPresence& operator=(const AccountPresence&) = delete;

    void mark_active(const std::uint32_t account_id) noexcept {
        account_id_ = account_id;
    }

    ~AccountPresence() {
        if (account_id_ == 0U) return;
        try {
            database::MysqlConnection database{config_};
            database.set_account_active(account_id_, false);
        } catch (...) {
            // A dropped game session must not throw through the socket worker.
        }
    }

private:
    config::DatabaseConfig config_;
    std::uint32_t account_id_{};
};

[[nodiscard]] bool handle_login(const SOCKET socket, std::vector<std::byte>& frame,
        const config::DatabaseConfig& database_config, const std::uint16_t client_id,
        AccountPresence& presence, GameSession& session,
        auth::LoginGrantRegistry& login_grants) {
    const auto reject = [client_id](const char* reason) {
        std::clog << "[game] login rejected client=" << client_id
                  << " reason=" << reason << std::endl;
        return false;
    };
    (void)protocol::decrypt_frame(frame);
    const auto decoded = protocol::decode_header(frame);
    if (!decoded) return reject("invalid packet header");
    if (decoded.header.opcode != login_opcode)
        return reject("unexpected first opcode");
    if (frame.size() < 76U) return reject("login packet shorter than username and token fields");

    // Delphi passes a fixed 22,000-byte receive buffer to CheckLogin even
    // when the packet's declared size is only 100 bytes. Preserve that field
    // access behavior while keeping the decoder's actual frame size intact.
    const auto received_frame_size = frame.size();
    if (frame.size() < 259U) frame.resize(259U, std::byte{0});

    const auto bytes = std::span<const std::byte>{frame};
    const auto username = fixed_string(bytes, 16U, 32U);
    const std::array<std::size_t, 3U> token_offsets{72U, 227U, 44U};
    std::array<std::string, 3U> tokens{};
    for (std::size_t i = 0U; i < token_offsets.size(); ++i)
        tokens[i] = fixed_string(bytes, token_offsets[i], 32U);
    if (username.empty())
        return reject("login fields missing");

    database::MysqlConnection database{database_config};
    const auto account = database.find_account(username);
    if (!account.has_value()) return reject("account not found");
    if (account->account_status == 8U) return reject("account banned");
    auto saved_token = account->last_token;
    std::transform(saved_token.begin(), saved_token.end(), saved_token.begin(),
        [](const unsigned char c) {
            return static_cast<char>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
        });
    const auto age = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() -
        account->last_token_creation_time;
    const auto token_matches = [&saved_token](std::string candidate) {
        std::transform(candidate.begin(), candidate.end(), candidate.begin(),
            [](const unsigned char c) {
                return static_cast<char>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
            });
        return candidate == saved_token;
    };
    std::size_t matched_token_offset{};
    bool token_prefix_matches_saved{};
    for (std::size_t i = 0U; i < tokens.size(); ++i) {
        if (!tokens[i].empty() && token_matches(tokens[i])) {
            matched_token_offset = token_offsets[i];
            break;
        }
        if (tokens[i].size() >= 8U && tokens[i].size() < saved_token.size() &&
            saved_token.compare(0U, tokens[i].size(), tokens[i]) == 0) {
            token_prefix_matches_saved = true;
        }
    }
    const bool grant_authorized = matched_token_offset == 0U &&
        login_grants.consume(username, account->id, peer_ipv4_address(socket));
    if (matched_token_offset == 0U && !grant_authorized) {
        for (std::size_t offset = 12U; offset + 32U <= received_frame_size; ++offset) {
            const auto candidate = fixed_string(bytes, offset, 32U);
            if (!candidate.empty() && token_matches(candidate)) {
                matched_token_offset = offset;
                break;
            }
        }
    }
    if (matched_token_offset == 0U && !grant_authorized) {
        std::clog << "[game] login token fields client=" << client_id
                  << " frame_bytes=" << received_frame_size
                  << " username_bytes=" << username.size()
                  << " token_lengths=" << tokens[0].size() << ','
                  << tokens[1].size() << ',' << tokens[2].size()
                  << " saved_token_bytes=" << saved_token.size()
                  << " token_prefix_matches_saved="
                  << (token_prefix_matches_saved ? "yes" : "no")
                  << " match=no" << std::endl;
        return reject("token mismatch");
    }
    if (grant_authorized) {
        std::clog << "[game] login handoff accepted client=" << client_id
                  << " source=validated-login-listener" << std::endl;
    } else {
        std::clog << "[game] login token fields client=" << client_id
                  << " frame_bytes=" << received_frame_size
                  << " username_bytes=" << username.size()
                  << " token_match_offset=" << matched_token_offset << std::endl;
    }
    if (age >= 300) return reject("token expired");

    auto characters = database.load_characters(account->id);
    database.set_account_active(account->id, true);
    presence.mark_active(account->id);
    session.account = *account;
    session.characters = std::move(characters);
    auto response = make_character_list(session.account, session.characters, client_id);
    std::vector<std::byte> output(response.begin(), response.end());
    if (!send_encrypted(socket, output)) return reject("character list send failed");
    session.authenticated = true;
    std::clog << "[game] login accepted client=" << client_id
              << " characters=" << session.characters.size() << std::endl;
    return true;
}

[[nodiscard]] bool equal_ascii_case_insensitive(std::string left,
        std::string right) {
    const auto lower = [](std::string& value) {
        std::transform(value.begin(), value.end(), value.begin(),
            [](const unsigned char c) {
                return static_cast<char>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
            });
    };
    lower(left);
    lower(right);
    return left == right;
}

[[nodiscard]] bool handle_numeric_token(const SOCKET socket,
        std::vector<std::byte>& frame, const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session) {
    const auto decoded = protocol::decode_header(frame);
    if (!decoded || decoded.header.opcode != numeric_token_opcode || frame.size() < 28U)
        return false;
    const auto bytes = std::span<const std::byte>{frame};
    const auto slot = read_u32(bytes, 12U);
    const auto action = read_u32(bytes, 16U);
    if (slot >= 3U) {
        std::clog << "[game] PIN request rejected client=" << client_id
                  << " reason=invalid-slot slot=" << slot << std::endl;
        return false;
    }
    const auto found = std::find_if(session.characters.begin(), session.characters.end(),
        [slot](const database::CharacterRecord& character) {
            return character.slot == slot;
        });
    if (found == session.characters.end() || found->numeric_errors >= 5U) {
        std::clog << "[game] PIN request rejected client=" << client_id
                  << " slot=" << slot
                  << " reason=" << (found == session.characters.end()
                      ? "character-not-found" : "pin-attempt-limit")
                  << std::endl;
        return false;
    }

    const auto new_token = fixed_bytes(bytes, 20U, 4U);
    const auto pin_digits_present = std::any_of(new_token.begin(), new_token.end(),
        [](const char value) { return value != '\0' && value != ' '; });
    std::clog << "[game] PIN request client=" << client_id
              << " slot=" << slot << " action=" << action
              << " pin_registered=" << (found->numeric_token.empty() ? "no" : "yes")
              << " stored_pin_length=" << found->numeric_token.size()
              << " pin_digits_present="
              << (pin_digits_present ? "yes" : "no")
              << std::endl;

    const auto previous_token = fixed_bytes(bytes, 24U, 4U);
    bool changed = false;
    bool enter_world = false;
    bool resend_character_list = false;
    switch (action) {
    case 0U:
        if (found->numeric_token.empty()) {
            if (new_token.empty()) {
                std::clog << "[game] PIN registration rejected client=" << client_id
                          << " slot=" << slot << " reason=empty-pin" << std::endl;
                auto list = make_character_list(session.account,
                    session.characters, client_id);
                std::vector<std::byte> output(list.begin(), list.end());
                return send_encrypted(socket, output);
            }
            found->numeric_token = new_token;
            changed = true;
            enter_world = true;
        } else if (equal_ascii_case_insensitive(new_token, found->numeric_token)) {
            // Some compatible clients send RequestChange=0 for both first-time
            // registration and ordinary PIN verification. Keep Delphi's empty-PIN
            // registration behavior and accept that client variant on existing PINs.
            found->numeric_errors = 0U;
            changed = true;
            enter_world = true;
        } else {
            ++found->numeric_errors;
            changed = true;
            resend_character_list = true;
        }
        break;
    case 1U:
        if (equal_ascii_case_insensitive(new_token, found->numeric_token)) {
            found->numeric_errors = 0U;
            changed = true;
            enter_world = true;
        } else {
            ++found->numeric_errors;
            changed = true;
            resend_character_list = true;
        }
        break;
    case 2U:
        if (equal_ascii_case_insensitive(previous_token, found->numeric_token)) {
            found->numeric_token = new_token;
            changed = true;
            enter_world = true;
        } else {
            ++found->numeric_errors;
            changed = true;
        }
        break;
    default:
        std::clog << "[game] PIN request rejected client=" << client_id
                  << " slot=" << slot << " reason=unsupported-action" << std::endl;
        return true;
    }
    if (!changed) {
        std::clog << "[game] PIN request ignored client=" << client_id
                  << " slot=" << slot << " action=" << action
                  << " reason=state-mismatch" << std::endl;
        return true;
    }

    try {
        database::MysqlConnection database{database_config};
        database.save_character_numeric(found->id, found->numeric_token,
            found->numeric_errors);
    } catch (const std::exception& error) {
        std::clog << "[game] PIN persistence failed client=" << client_id
                  << " slot=" << slot << " reason=" << error.what() << std::endl;
        return false;
    }
    if (!enter_world) {
        if (!send_encrypted(socket, frame)) return false;
        if (resend_character_list) {
            auto list = make_character_list(session.account, session.characters, client_id);
            std::vector<std::byte> output(list.begin(), list.end());
            return send_encrypted(socket, output);
        }
        std::clog << "[game] PIN verification failed client=" << client_id
                  << " slot=" << slot << " errors="
                  << static_cast<unsigned>(found->numeric_errors) << std::endl;
        return true;
    }

    std::vector<database::CharacterRecord> detailed;
    try {
        database::MysqlConnection connection{database_config};
        detailed = connection.load_characters(session.account.id, true);
    } catch (const std::exception& error) {
        std::clog << "[game] character load after PIN failed client=" << client_id
                  << " slot=" << slot << " reason=" << error.what() << std::endl;
        return false;
    }
    const auto selected = std::find_if(detailed.begin(), detailed.end(),
        [slot](const database::CharacterRecord& character) {
            return character.slot == slot;
        });
    if (selected == detailed.end()) return false;
    auto selected_character = *selected;

    // Delphi's legacy-character loader materializes the built-in backpack as
    // Inventory[60] = {Index=5300, APP=5300, Refi=1}. C++ character creation
    // used to persist Index=5300 with APP/Refi left zero, which suppresses the
    // first backpack icon in the client's right-side bag selector. Repair the
    // marker in memory and in SQL before sending the world-character record.
    auto& main_backpack = selected_character.inventory[60U];
    if (main_backpack.item_id == 5300U &&
        (main_backpack.app != 5300U || main_backpack.refine != 1U)) {
        main_backpack.app = 5300U;
        main_backpack.refine = 1U;
        try {
            database::MysqlConnection connection{database_config};
            connection.save_character_items(selected_character.id,
                selected_character.gold,
                {{1U, 60U, main_backpack}});
            std::clog << "[game] repaired main backpack marker client="
                      << client_id << " slot=60 app=5300 refine=1" << std::endl;
        } catch (const std::exception& error) {
            std::clog << "[game] main backpack marker repair failed client="
                      << client_id << " reason=" << error.what() << std::endl;
            return false;
        }
    }

    // Delphi always activates the Traveler's Symbol into Inventory[63]. The
    // earlier C++ implementation chose the first free slot (61), leaving the
    // active bag visible in a noncanonical side slot and making the client send
    // clicks for a different bag index. Migrate that legacy placement without
    // disturbing characters that already have a bag in slot 63.
    if (selected_character.inventory[63U].item_id == 0U) {
        std::optional<std::uint16_t> misplaced_bag_slot;
        constexpr std::array<std::uint16_t, 2U> legacy_bag_slots{61U, 62U};
        for (const auto candidate : legacy_bag_slots) {
            const auto item_id = selected_character.inventory[candidate].item_id;
            if (item_id != 0U && item_id < tables.item_definitions.size() &&
                tables.item_definitions[item_id].item_type == 217U) {
                misplaced_bag_slot = candidate;
                break;
            }
        }
        if (misplaced_bag_slot.has_value()) {
            try {
                database::MysqlConnection connection{database_config};
                if (!connection.move_character_item(selected_character.id, 1U,
                        *misplaced_bag_slot, 1U, 63U)) {
                    std::clog << "[game] inventory bag slot migration failed client="
                              << client_id << " source_slot=" << *misplaced_bag_slot
                              << " destination_slot=63 reason=item-row-not-found"
                              << std::endl;
                    return false;
                }
                selected_character.inventory[63U] =
                    selected_character.inventory[*misplaced_bag_slot];
                selected_character.inventory[*misplaced_bag_slot] = {};
                std::clog << "[game] inventory bag slot migrated client=" << client_id
                          << " source_slot=" << *misplaced_bag_slot
                          << " destination_slot=63 item_id="
                          << selected_character.inventory[63U].item_id << std::endl;
            } catch (const std::exception& error) {
                std::clog << "[game] inventory bag slot migration failed client="
                          << client_id << " reason=" << error.what() << std::endl;
                return false;
            }
        }
    }

    const auto [max_hp, max_mp] = estimate_max_hp_mp(selected_character, tables);
    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    const auto character_age = now - selected_character.creation_time;
    std::clog << "[game] selected character state client=" << client_id
              << " hp=" << selected_character.current_hp << '/' << max_hp
              << " mp=" << selected_character.current_mp << '/' << max_mp
              << " age_seconds=" << character_age << std::endl;
    if (character_age >= 0 && character_age <= 1800 && max_hp > 0U && max_mp > 0U &&
        selected_character.current_hp == max_hp / 10U &&
        selected_character.current_mp == max_mp / 10U) {
        selected_character.current_hp = max_hp;
        selected_character.current_mp = max_mp;
        try {
            database::MysqlConnection connection{database_config};
            connection.save_character_items(selected_character.id,
                selected_character.gold, {}, {}, std::pair{max_hp, max_mp});
        } catch (const std::exception& error) {
            std::clog << "[game] fresh character repair failed client=" << client_id
                      << " slot=" << slot << " reason=" << error.what() << std::endl;
            return false;
        }
        std::clog << "[game] repaired fresh character vitals client=" << client_id
                  << " reason=initial spawn had revive-level HP and MP" << std::endl;
    }
    session.selected_character = selected_character;
    session.world_packet_sent = true;
    std::clog << "[game] inventory bag markers client=" << client_id
              << " main=" << selected_character.inventory[60U].item_id << '/'
              << selected_character.inventory[60U].app << '/'
              << selected_character.inventory[60U].refine
              << " extra=" << selected_character.inventory[61U].item_id << ','
              << selected_character.inventory[62U].item_id << ','
              << selected_character.inventory[63U].item_id << std::endl;
    std::clog << "[game] PIN accepted client=" << client_id
              << " slot=" << slot << " action=" << action << std::endl;
    for (unsigned i = 0U; i < 4U; ++i) {
        const auto signal = make_signal_packet(client_id,
            i == 0U ? 0xccccU : 0x0186U, 1U);
        std::vector<std::byte> output(signal.begin(), signal.end());
        if (!send_encrypted(socket, output)) {
            std::clog << "[game] world handoff failed client=" << client_id
                      << " stage=signal index=" << i << std::endl;
            return false;
        }
    }
    auto world_packet = make_world_character_packet(session.account, selected_character,
        client_id, tables);
    const auto sent = send_encrypted(socket, world_packet);
    std::clog << "[game] world character packet client=" << client_id
              << " bytes=" << world_packet.size()
              << " result=" << (sent ? "sent" : "send-failed") << std::endl;
    return sent;
}

[[nodiscard]] bool handle_enter_world(const SOCKET socket,
        const std::uint16_t client_id, const data::GameTables& tables,
        const std::shared_ptr<GameSession>& session,
        ChannelRuntime& runtime) {
    auto& state = *session;
    if (!state.world_packet_sent || !state.selected_character.has_value()) return false;
    if (state.entered_world) return true;
    const auto& character = *state.selected_character;
    std::clog << "[game] world initialization client=" << client_id
              << " hp=" << character.current_hp
              << " move_speed=" << character.move_speed
              << " spawn_move_speed=" << (character.move_speed == 0U
                    ? calculate_combat_status(character, tables).move_speed
                    : character.move_speed)
              << " position=" << character.position_x << ',' << character.position_y
              << std::endl;
    auto spawn = make_create_mob_packet(state.account, character, client_id, tables);
    if (!send_encrypted(socket, spawn)) {
        std::clog << "[game] world initialization failed client=" << client_id
                  << " stage=character-spawn" << std::endl;
        return false;
    }
    auto status = make_refresh_status_packet(character, tables);
    if (!send_encrypted(socket, status)) {
        std::clog << "[game] world initialization failed client=" << client_id
                  << " stage=status" << std::endl;
        return false;
    }
    auto skills = make_player_skills_packet(character, client_id);
    if (!send_encrypted(socket, skills)) {
        std::clog << "[game] world initialization failed client=" << client_id
                  << " stage=skills" << std::endl;
        return false;
    }
    auto points = make_refresh_points_packet(character);
    if (!send_encrypted(socket, points)) {
        std::clog << "[game] world initialization failed client=" << client_id
                  << " stage=points" << std::endl;
        return false;
    }
    auto level = make_refresh_level_packet(character, client_id);
    if (!send_encrypted(socket, level)) {
        std::clog << "[game] world initialization failed client=" << client_id
                  << " stage=level" << std::endl;
        return false;
    }
    auto hp_mp = make_current_hp_mp_packet(character, client_id, tables);
    if (!send_encrypted(socket, hp_mp)) {
        std::clog << "[game] world initialization failed client=" << client_id
                  << " stage=hp-mp" << std::endl;
        return false;
    }
    auto buffs = make_refresh_buffs_packet(character, client_id, tables);
    if (!send_encrypted(socket, buffs)) {
        std::clog << "[game] world initialization failed client=" << client_id
                  << " stage=buffs" << std::endl;
        return false;
    }
    const auto entered = runtime.enter_world(session, tables);
    if (!entered) {
        std::clog << "[game] world initialization failed client=" << client_id
                  << " stage=visibility" << std::endl;
        return false;
    }

    // Delphi sends the player's own $0349 spawn a second time after loading
    // status, skills, buffs, and visibility. The client uses this final entity
    // state when enabling world interaction and movement.
    if (!runtime.refresh_player_spawn(*session, tables)) {
        std::clog << "[game] world initialization failed client=" << client_id
                  << " stage=final-player-spawn" << std::endl;
        return false;
    }
    std::clog << "[game] final player spawn client=" << client_id
              << " result=sent" << std::endl;
    std::clog << "[game] world initialization "
              << "complete client=" << client_id << std::endl;
    return true;
}

[[nodiscard]] std::uint32_t initial_skill_index(const std::uint32_t job,
        const std::uint32_t skill, const std::uint32_t level) noexcept {
    std::uint32_t index = job > 1U ? (job - 1U) * 960U : 1U;
    if (skill > 1U) index += (skill - 1U) * 16U;
    if (job == 1U) {
        if (level > 1U) index += level - 1U;
    } else {
        index += level > 1U ? level - 1U : level;
    }
    return index;
}

using InitialSkillList = std::array<std::array<std::uint16_t, 2U>, 46U>;

[[nodiscard]] InitialSkillList load_initial_skills(const std::uint32_t job) {
    constexpr std::array<std::string_view, 6U> filenames{
        "Guerreiro.acc", "Templaria.acc", "Atirador.acc",
        "Pistoleira.acc", "Feiticeiro.acc", "Cleriga.acc"};
    constexpr std::streamoff skills_offset = 4265;
    constexpr std::size_t skill_list_bytes = 46U * 4U;
    InitialSkillList result{};
    if (job < filenames.size()) {
        const auto path = std::filesystem::path{"C:/Database/BaseAccs"} /
            filenames[job];
        std::ifstream input{path, std::ios::binary};
        if (input) {
            input.seekg(skills_offset);
            std::array<unsigned char, skill_list_bytes> bytes{};
            if (input.read(reinterpret_cast<char*>(bytes.data()),
                    static_cast<std::streamsize>(bytes.size()))) {
                for (std::size_t i = 0U; i < result.size(); ++i) {
                    result[i][0] = static_cast<std::uint16_t>(bytes[i * 4U] |
                        (static_cast<std::uint16_t>(bytes[i * 4U + 1U]) << 8U));
                    result[i][1] = static_cast<std::uint16_t>(bytes[i * 4U + 2U] |
                        (static_cast<std::uint16_t>(bytes[i * 4U + 3U]) << 8U));
                }
                return result;
            }
        }
    }

    // Delphi creates a default .acc when the class template is absent.
    for (std::uint32_t slot = 0U; slot < 6U; ++slot) {
        result[slot] = {static_cast<std::uint16_t>(initial_skill_index(
            job + 1U, slot + 1U, 1U)), static_cast<std::uint16_t>(slot < 4U ? 1U : 0U)};
    }
    for (std::uint32_t slot = 0U; slot < 40U; ++slot) {
        result[slot + 6U] = {static_cast<std::uint16_t>(initial_skill_index(
            job + 1U, slot + 7U, 1U)), static_cast<std::uint16_t>(slot == 0U ? 1U : 0U)};
    }
    return result;
}

[[nodiscard]] std::optional<database::NewCharacterData> make_new_character(
        const std::span<const std::byte> request, const data::GameTables& tables) {
    if (request.size() < 56U) return std::nullopt;
    const auto slot = read_u32(request, 16U);
    const auto name = fixed_bytes(request, 20U, 16U);
    const auto class_index = read_u16(request, 36U);
    const auto hair = read_u16(request, 38U);
    const auto local = read_u32(request, 52U);
    if (slot > 2U || name.empty() || name.size() > 14U ||
        class_index < 10U || class_index > 69U || hair < 7700U || hair > 7731U ||
        local > 1U || !std::all_of(name.begin(), name.end(), [](const unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9');
        })) return std::nullopt;

    const auto job = static_cast<std::uint32_t>(class_index / 10U - 1U);
    if (job >= 6U) return std::nullopt;
    constexpr std::array<std::array<std::uint16_t, 5U>, 6U> base_attributes{{
        {{15U, 9U, 5U, 16U, 0U}}, {{14U, 10U, 6U, 14U, 0U}},
        {{8U, 16U, 9U, 12U, 5U}}, {{8U, 14U, 10U, 12U, 6U}},
        {{7U, 9U, 16U, 8U, 10U}}, {{7U, 10U, 15U, 9U, 9U}},
    }};
    struct StarterEquipment final {
        std::uint16_t slot;
        std::uint16_t item;
        std::uint16_t durability;
    };
    constexpr std::array<std::array<StarterEquipment, 4U>, 6U> starter_equipment{{
        {{{3U, 1719U, 100U}, {5U, 1779U, 100U}, {6U, 1069U, 160U}, {0U, 0U, 0U}}},
        {{{3U, 1839U, 120U}, {5U, 1899U, 120U}, {6U, 1034U, 140U}, {7U, 1309U, 120U}}},
        {{{3U, 1959U, 80U}, {5U, 2019U, 80U}, {6U, 1209U, 160U}, {7U, 1359U, 100U}}},
        {{{3U, 2079U, 80U}, {5U, 2139U, 80U}, {6U, 1174U, 140U}, {0U, 0U, 0U}}},
        {{{3U, 2199U, 60U}, {5U, 2259U, 60U}, {6U, 1279U, 160U}, {0U, 0U, 0U}}},
        {{{3U, 2319U, 60U}, {5U, 2379U, 60U}, {6U, 1244U, 140U}, {0U, 0U, 0U}}},
    }};

    database::NewCharacterData result{};
    auto& character = result.character;
    character.slot = slot;
    character.name = name;
    character.class_info = static_cast<std::uint16_t>(1U + job * 10U);
    std::copy(base_attributes[job].begin(), base_attributes[job].end(),
        character.attributes.begin());
    character.level = 1U;
    character.sizes = {7U, 119U, 119U, 0U};
    character.creation_time = static_cast<std::uint32_t>(std::time(nullptr));
    character.position_x = local == 0U ? 3432.0F : 3443.0F;
    character.position_y = local == 0U ? 672.0F : 912.0F;

    const auto add_item = [&result](const std::uint8_t type, const std::uint16_t item_slot,
            const std::uint32_t item_id, const std::uint32_t app,
            const std::uint32_t min, const std::uint32_t max,
            const std::uint32_t refine) {
        database::CharacterItem item{};
        item.item_id = item_id;
        item.app = app;
        item.min = min;
        item.max = max;
        item.refine = refine;
        result.items.push_back({type, item_slot, item});
    };
    add_item(0U, 0U, class_index, 0U, 0U, 0U, 0U);
    add_item(0U, 1U, hair, 0U, 0U, 0U, 0U);
    for (const auto& equipment : starter_equipment[job]) {
        if (equipment.item == 0U) continue;
        add_item(0U, equipment.slot, equipment.item, equipment.item,
            equipment.durability, equipment.durability, 0U);
    }
    constexpr std::array<std::array<std::uint32_t, 3U>, 5U> starter_inventory{{
        {{4350U, 0U, 10U}}, {{4390U, 1U, 10U}}, {{10044U, 2U, 1U}},
        {{5284U, 3U, 1U}}, {{5300U, 60U, 1U}},
    }};
    for (const auto& entry : starter_inventory)
        add_item(1U, static_cast<std::uint16_t>(entry[1]), entry[0],
            entry[0] == 5300U ? 5300U : 0U,
            0U, 0U, entry[2]);
    if (job == 2U || job == 3U) {
        const auto ammunition = job == 2U ? 4615U : 4600U;
        add_item(1U, 5U, ammunition, ammunition, 0U, 0U, 1000U);
        add_item(1U, 6U, ammunition, ammunition, 0U, 0U, 1000U);
    }

    const auto initial_skills = load_initial_skills(job);
    for (std::uint32_t skill_slot = 0U; skill_slot < 6U; ++skill_slot)
        result.skills.push_back({static_cast<std::uint16_t>(skill_slot),
            initial_skills[skill_slot][0], initial_skills[skill_slot][1], 1U});
    for (std::uint32_t skill_slot = 0U; skill_slot < 40U; ++skill_slot)
        result.skills.push_back({static_cast<std::uint16_t>(skill_slot),
            initial_skills[skill_slot + 6U][0], initial_skills[skill_slot + 6U][1], 2U});

    const auto bar_skill = [job](const std::uint32_t skill, const std::uint32_t level) {
        return initial_skill_index(job + 1U, skill, level) * 16U + 2U;
    };
    result.item_bar[0U] = bar_skill(1U, 1U);
    result.item_bar[1U] = bar_skill(7U, 1U);
    result.item_bar[2U] = bar_skill(3U, 1U);
    result.item_bar[7U] = bar_skill(2U, 1U);
    if (job == 0U || job == 5U) result.item_bar[3U] = bar_skill(4U, 1U);

    for (const auto& placement : result.items) {
        if (placement.slot_type == 0U && placement.slot < character.equipment.size())
            character.equipment[placement.slot] = placement.item;
    }
    for (const auto& skill : result.skills) {
        const auto character_slot = static_cast<std::size_t>(skill.slot) +
            (skill.type == 2U ? 6U : 0U);
        if (character_slot < character.skills.size())
            character.skills[character_slot] = {skill.item, skill.level};
    }
    const auto [max_hp, max_mp] = estimate_max_hp_mp(character, tables);
    character.current_hp = max_hp;
    character.current_mp = max_mp;
    return result;
}

[[nodiscard]] bool handle_create_character(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session) {
    const auto created = make_new_character(request, tables);
    if (!created.has_value()) {
        std::clog << "[game] character creation rejected client=" << client_id
                  << " reason=invalid request fields bytes=" << request.size()
                  << std::endl;
        return true;
    }
    try {
        database::MysqlConnection database{database_config};
        if (!database.create_character(session.account.id, *created)) {
            std::clog << "[game] character creation rejected client=" << client_id
                      << " reason=account limit slot or duplicate name" << std::endl;
            return true;
        }
        session.characters = database.load_characters(session.account.id);
    } catch (const std::exception& error) {
        std::clog << "[game] character creation failed client=" << client_id
                  << " reason=database error: " << error.what() << std::endl;
        OutputDebugStringA((std::string{"Aika character creation failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    std::clog << "[game] character creation stored client=" << client_id
              << " characters=" << session.characters.size() << std::endl;
    auto list = make_character_list(session.account, session.characters, client_id);
    std::vector<std::byte> output(list.begin(), list.end());
    return send_encrypted(socket, output);
}

[[nodiscard]] bool send_current_character_list(const SOCKET socket,
        const std::uint16_t client_id, const GameSession& session) {
    auto list = make_character_list(session.account, session.characters, client_id);
    std::vector<std::byte> output(list.begin(), list.end());
    return send_encrypted(socket, output);
}

[[nodiscard]] bool handle_request_character_deletion(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const config::GameRules& rules, const std::uint16_t client_id,
        GameSession& session) {
    if (request.size() < 28U) return true;
    const auto slot = read_u32(request, 16U);
    if (slot >= 3U) return send_current_character_list(socket, client_id, session);
    auto character = std::find_if(session.characters.begin(), session.characters.end(),
        [slot](const database::CharacterRecord& current) { return current.slot == slot; });
    if (character == session.characters.end())
        return send_current_character_list(socket, client_id, session);

    const auto cancel_requested = read_u32(request, 20U) != 0U;
    const auto numeric = fixed_bytes(request, 24U, 4U);
    if (cancel_requested &&
        !equal_ascii_case_insensitive(character->numeric_token, numeric))
        return send_current_character_list(socket, client_id, session);
    if (cancel_requested && character->deleted) {
        try {
            database::MysqlConnection database{database_config};
            database.save_character_deletion(character->id, false, {});
            character->deleted = false;
            character->delete_time.clear();
        } catch (const std::exception& error) {
            OutputDebugStringA((std::string{"Aika character deletion cancellation failed: "} +
                error.what() + "\n").c_str());
        }
        return send_current_character_list(socket, client_id, session);
    }

    if (character->name.empty() || character->numeric_token.empty() ||
        character->numeric_token != numeric)
        return send_current_character_list(socket, client_id, session);
    if (!character->deleted) {
        const auto delete_time = local_datetime_after_days(rules.delete_days_increment);
        if (delete_time.empty()) return true;
        try {
            database::MysqlConnection database{database_config};
            database.save_character_deletion(character->id, true, delete_time);
            character->deleted = true;
            character->delete_time = delete_time;
        } catch (const std::exception& error) {
            OutputDebugStringA((std::string{"Aika character deletion request failed: "} +
                error.what() + "\n").c_str());
        }
        return send_current_character_list(socket, client_id, session);
    }

    const auto delete_at = parse_local_datetime(character->delete_time);
    if (!delete_at.has_value() || *delete_at < std::time(nullptr))
        return send_current_character_list(socket, client_id, session);
    return true;
}

[[nodiscard]] bool handle_delete_character(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, GameSession& session) {
    if (request.size() < 24U) return true;
    const auto slot = read_u32(request, 16U);
    if (slot >= 3U) return send_current_character_list(socket, client_id, session);
    auto character = std::find_if(session.characters.begin(), session.characters.end(),
        [slot](const database::CharacterRecord& current) { return current.slot == slot; });
    if (character == session.characters.end() || !character->deleted ||
        character->name.empty())
        return send_current_character_list(socket, client_id, session);

    const auto numeric = fixed_bytes(request, 20U, 4U);
    if (!character->numeric_token.empty() && character->numeric_token != numeric)
        return send_current_character_list(socket, client_id, session);
    const auto delete_at = parse_local_datetime(character->delete_time);
    if (!delete_at.has_value() || std::time(nullptr) < *delete_at)
        return send_current_character_list(socket, client_id, session);

    const auto character_id = character->id;
    try {
        database::MysqlConnection database{database_config};
        if (!database.delete_character(character_id))
            return send_current_character_list(socket, client_id, session);
        session.characters.erase(character);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika character deletion failed: "} +
            error.what() + "\n").c_str());
        return send_current_character_list(socket, client_id, session);
    }
    return send_current_character_list(socket, client_id, session);
}

[[nodiscard]] std::optional<std::uint32_t> character_job(
        const std::uint16_t class_info) noexcept {
    if (class_info >= 1U && class_info <= 9U) return 0U;
    if (class_info >= 11U && class_info <= 19U) return 1U;
    if (class_info >= 21U && class_info <= 29U) return 2U;
    if (class_info >= 31U && class_info <= 39U) return 3U;
    if (class_info >= 41U && class_info <= 49U) return 4U;
    if (class_info >= 51U && class_info <= 59U) return 5U;
    return std::nullopt;
}

[[nodiscard]] bool send_client_message(const SOCKET socket,
        const std::string_view message, const std::uint16_t client_id) {
    auto packet = make_client_message_packet(message, client_id);
    return send_encrypted(socket, packet);
}

[[nodiscard]] bool handle_learn_skill(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session) {
    if (request.size() < 20U || !session.entered_world ||
        !session.selected_character.has_value()) return true;
    auto& character = *session.selected_character;
    const auto skill_index = read_u32(request, 12U);
    const auto npc_index = read_u32(request, 16U);
    if (skill_index == 0U || skill_index >= tables.skill_definitions.size()) return true;
    const auto& definition = tables.skill_definitions[skill_index];
    if (definition.index == 427U) {
        return send_client_message(socket,
            "Esta habilidade não está disponível.", client_id);
    }
    if (session.skill_upgraded == skill_index) return true;

    const bool is_gm = session.account.account_type == 4U;
    if (!is_gm) {
        const auto job = character_job(character.class_info);
        const auto skill_job = definition.class_id <= 59U
            ? character_job(static_cast<std::uint16_t>(definition.class_id))
            : std::nullopt;
        if (!job.has_value() || (definition.class_id != 0U &&
                (!skill_job.has_value() || *skill_job != *job))) {
            return send_client_message(socket,
                "Esta habilidade não pertence a sua classe.", client_id);
        }
        if (definition.min_level > character.level)
            return send_client_message(socket, "Não possui level necessário.", client_id);
        if (definition.skill_points > character.skill_points)
            return send_client_message(socket,
                "Não possui pontos de habilidade necessário.", client_id);
        if (definition.learn_cost > character.gold)
            return send_client_message(socket, "Não possui gold suficiente.", client_id);
    }

    std::size_t skill_slot = character.skills.size();
    std::uint8_t skill_type{};
    for (std::size_t i = 0U; i < character.skills.size(); ++i) {
        const auto base = static_cast<std::uint32_t>(character.skills[i][0]);
        if (base != 0U && skill_index >= base && skill_index <= base + 15U) {
            skill_slot = i < 6U ? i : i - 6U;
            skill_type = i < 6U ? 1U : 2U;
            break;
        }
    }
    if (skill_slot >= 40U) return true;
    const auto record_index = skill_type == 1U ? skill_slot : skill_slot + 6U;
    const auto& old_skill = character.skills[record_index];
    if (old_skill[1] == (std::numeric_limits<std::uint16_t>::max)()) return true;
    const auto new_level = static_cast<std::uint16_t>(old_skill[1] + 1U);
    auto attributes = character.attributes;
    auto remaining_skill_points = character.skill_points;
    auto remaining_gold = character.gold;
    if (!is_gm) {
        if (remaining_skill_points == 1U) {
            attributes[5U] = 0U;
            remaining_skill_points = 0U;
        } else {
            remaining_skill_points = static_cast<std::uint16_t>(
                remaining_skill_points - definition.skill_points);
        }
        remaining_gold -= definition.learn_cost;
    }
    std::vector<std::pair<std::uint8_t, std::uint32_t>> updated_bars;
    for (std::size_t i = 0U; i < character.item_bar.size(); ++i) {
        const auto item = character.item_bar[i];
        if (item < 2U) continue;
        const auto mapped_skill = static_cast<std::uint32_t>(std::nearbyint(
            static_cast<double>(item - 2U) / 16.0));
        if (mapped_skill == skill_index - 1U)
            updated_bars.emplace_back(static_cast<std::uint8_t>(i),
                skill_index * 16U + 2U);
    }

    try {
        database::MysqlConnection database{database_config};
        database.learn_character_skill(character.id,
            static_cast<std::uint16_t>(skill_slot), skill_type, old_skill[0],
            new_level, attributes, remaining_skill_points, remaining_gold,
            updated_bars);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika skill-learning persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }

    character.skills[record_index][1] = new_level;
    character.attributes = attributes;
    character.skill_points = remaining_skill_points;
    character.gold = remaining_gold;
    for (const auto& [bar_slot, item] : updated_bars)
        character.item_bar[bar_slot] = item;
    session.skill_upgraded = skill_index;

    auto learned_skills = make_player_skills_packet(character, client_id, npc_index);
    if (!send_encrypted(socket, learned_skills)) return false;
    auto money = make_refresh_money_packet(character, session.account);
    std::vector<std::byte> money_packet(money.begin(), money.end());
    if (!send_encrypted(socket, money_packet)) return false;
    auto skill_levels = make_skill_levels_packet(character, tables, client_id);
    if (!send_encrypted(socket, skill_levels)) return false;
    auto hp_mp = make_current_hp_mp_packet(character, client_id, tables);
    if (!send_encrypted(socket, hp_mp)) return false;
    auto status = make_refresh_status_packet(character, tables);
    if (!send_encrypted(socket, status)) return false;
    auto points = make_refresh_points_packet(character);
    if (!send_encrypted(socket, points)) return false;
    for (const auto& [bar_slot, item] : updated_bars) {
        (void)item;
        auto bar = make_item_bar_packet(bar_slot, 2U, skill_index);
        std::vector<std::byte> bar_packet(bar.begin(), bar.end());
        if (!send_encrypted(socket, bar_packet)) return false;
    }
    if (is_gm && !send_client_message(socket,
            "[GM] Skill aprendida sem gastar gold / pontos / nível.", client_id))
        return false;
    return true;
}

[[nodiscard]] bool handle_reset_skills(const SOCKET socket,
        const config::DatabaseConfig& database_config, const std::uint16_t client_id,
        const data::GameTables& tables, GameSession& session) {
    if (!session.entered_world || !session.selected_character.has_value()) return true;
    auto& character = *session.selected_character;
    const auto job = character_job(character.class_info);
    if (!job.has_value()) return true;

    const bool is_gm = session.account.account_type == 5U;
    const auto cost = static_cast<std::uint64_t>(character.level) * 500U;
    if (!is_gm && character.gold < cost) {
        return send_client_message(socket,
            "Voc\u00ea n\u00e3o possui gold suficiente para reiniciar as suas habilidades!",
            client_id);
    }

    std::uint32_t points = character.level;
    for (const std::uint32_t threshold : {51U, 61U, 71U, 81U})
        if (character.level >= threshold) points += 12U;
    const auto restored_points = static_cast<std::uint16_t>(
        std::min<std::uint32_t>(points, (std::numeric_limits<std::uint16_t>::max)()));
    const auto remaining_gold = is_gm ? character.gold : character.gold - cost;

    const auto skill_template = load_initial_skills(*job);
    std::vector<database::CharacterSkillPlacement> initial_skills;
    initial_skills.reserve(skill_template.size());
    for (std::uint32_t slot = 0U; slot < 6U; ++slot)
        initial_skills.push_back({static_cast<std::uint16_t>(slot),
            skill_template[slot][0], skill_template[slot][1], 1U});
    for (std::uint32_t slot = 0U; slot < 40U; ++slot)
        initial_skills.push_back({static_cast<std::uint16_t>(slot),
            skill_template[slot + 6U][0], skill_template[slot + 6U][1], 2U});

    try {
        database::MysqlConnection database{database_config};
        database.reset_character_skills(character.id, initial_skills,
            restored_points, remaining_gold);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika skill-reset persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }

    character.skills.fill({});
    for (const auto& skill : initial_skills) {
        const auto target = skill.type == 1U ? skill.slot : skill.slot + 6U;
        if (target < character.skills.size())
            character.skills[target] = {skill.item, skill.level};
    }
    character.item_bar.fill(0U);
    character.skill_points = restored_points;
    character.gold = remaining_gold;
    session.skill_upgraded = 0U;

    auto skills = make_player_skills_packet(character, client_id);
    if (!send_encrypted(socket, skills)) return false;
    auto money = make_refresh_money_packet(character, session.account);
    std::vector<std::byte> money_packet(money.begin(), money.end());
    if (!send_encrypted(socket, money_packet)) return false;
    auto levels = make_skill_levels_packet(character, tables, client_id);
    if (!send_encrypted(socket, levels)) return false;
    auto hp_mp = make_current_hp_mp_packet(character, client_id, tables);
    if (!send_encrypted(socket, hp_mp)) return false;
    auto status = make_refresh_status_packet(character, tables);
    if (!send_encrypted(socket, status)) return false;
    auto points_packet = make_refresh_points_packet(character);
    if (!send_encrypted(socket, points_packet)) return false;
    for (std::uint32_t slot = 0U; slot < character.item_bar.size(); ++slot) {
        auto bar = make_item_bar_packet(slot, 0U, 0U);
        std::vector<std::byte> bar_packet(bar.begin(), bar.end());
        if (!send_encrypted(socket, bar_packet)) return false;
    }
    if (is_gm && !send_client_message(socket,
            "[GM] Skills resetadas sem custo.", client_id)) return false;
    return true;
}

[[nodiscard]] bool handle_remove_buff(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session, ChannelRuntime& runtime) {
    if (request.size() < 16U || !session.entered_world ||
        !session.selected_character.has_value()) return true;
    const auto buff_value = read_u32(request, 12U);
    if (buff_value == 0U || buff_value >= tables.skill_definitions.size() ||
        buff_value > (std::numeric_limits<std::uint16_t>::max)()) return true;
    auto& character = *session.selected_character;
    const auto buff_index = static_cast<std::uint16_t>(buff_value);
    try {
        database::MysqlConnection database{database_config};
        database.remove_character_buff(character.id, buff_index);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika buff-removal persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    for (auto& buff : character.buffs) {
        if (buff[0] == buff_index) buff = {};
    }

    if (!runtime.refresh_buffs(session, tables)) return false;
    auto hp_mp = make_current_hp_mp_packet(character, client_id, tables);
    if (!send_encrypted(socket, hp_mp)) return false;
    auto status = make_refresh_status_packet(character, tables);
    if (!send_encrypted(socket, status)) return false;
    auto points = make_refresh_points_packet(character);
    return send_encrypted(socket, points);
}

[[nodiscard]] bool handle_dismantle_item(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        database::CharacterRecord& character) {
    const auto inventory_slot = read_u16(request, 12U);
    if (inventory_slot >= 64U) return true;
    const auto& source_item = character.inventory[inventory_slot];
    if (source_item.item_id == 0U || source_item.item_id >= tables.item_definitions.size())
        return send_client_message(socket, "Este item nao pode ser desmontado.", client_id);
    const auto& definition = tables.item_definitions[source_item.item_id];
    const auto equip_slot = item_equip_slot(definition);
    if (!((equip_slot >= 2 && equip_slot <= 7) ||
          (equip_slot >= 11 && equip_slot <= 14)))
        return send_client_message(socket, "Este item nao pode ser desmontado.", client_id);

    if (definition.level == 0U)
        return send_client_message(socket, "Este item nao pode ser desmontado.", client_id);
    std::size_t range_index{};
    if (definition.level >= 1U && definition.level <= 20U) range_index = 0U;
    else if (definition.level <= 30U) range_index = 1U;
    else if (definition.level <= 40U) range_index = 2U;
    else if (definition.level <= 50U) range_index = 3U;
    else if (definition.level <= 60U) range_index = 4U;
    else if (definition.level <= 70U) range_index = 5U;
    else if (definition.level <= 80U) range_index = 6U;
    else if (definition.level <= 90U) range_index = 7U;
    else if (definition.level <= 99U) range_index = 8U;
    else return send_client_message(socket, "Este item nao pode ser desmontado.", client_id);

    constexpr std::array<std::array<std::uint16_t, 6U>, 9U> dismantle_rewards{{
        {{5100U, 5080U, 5081U, 5082U, 4630U, 4631U}},
        {{5100U, 5080U, 5081U, 5082U, 4632U, 4633U}},
        {{5100U, 5080U, 5081U, 5082U, 4634U, 4635U}},
        {{5100U, 5080U, 5081U, 5082U, 4636U, 4638U}},
        {{5100U, 5080U, 5081U, 5082U, 4642U, 4644U}},
        {{5100U, 5080U, 5081U, 5082U, 4644U, 4636U}},
        {{5100U, 5080U, 5081U, 5082U, 4642U, 4645U}},
        {{5100U, 5080U, 5081U, 5082U, 4649U, 4647U}},
        {{5100U, 5080U, 5081U, 5082U, 4649U, 4647U}},
    }};
    static thread_local std::mt19937 random_engine{std::random_device{}()};
    const auto reward_choice = std::uniform_int_distribution<std::size_t>{0U, 5U}(random_engine);
    const auto reward_id = dismantle_rewards[range_index][reward_choice];
    const auto reward_amount = std::uniform_int_distribution<std::uint32_t>{1U, 5U}(random_engine);
    if (reward_id >= tables.item_definitions.size())
        return send_client_message(socket, "Este item nao pode ser desmontado.", client_id);

    auto inventory = character.inventory;
    inventory[inventory_slot] = {};
    const auto& reward_definition = tables.item_definitions[reward_id];
    const bool stackable = reward_definition.can_group != 0U;
    auto remaining = reward_amount;
    std::vector<std::uint16_t> reward_slots;
    if (stackable) {
        for (std::uint16_t slot = 0U; slot < 60U && remaining > 0U; ++slot) {
            if (!is_inventory_slot_unlocked(inventory, slot)) continue;
            auto& current = inventory[slot];
            if (current.item_id != reward_id || current.refine >= 1000U) continue;
            const auto added = (std::min)(remaining, 1000U - current.refine);
            current.refine += added;
            remaining -= added;
            reward_slots.push_back(slot);
        }
    }
    while (remaining > 0U) {
        std::optional<std::uint16_t> empty;
        for (std::uint16_t slot = 0U; slot < 60U; ++slot) {
            if (inventory[slot].item_id != 0U) continue;
            if (!is_inventory_slot_unlocked(inventory, slot)) continue;
            empty = slot;
            break;
        }
        if (!empty.has_value())
            return send_client_message(socket, "Inventario cheio.", client_id);
        auto& reward = inventory[*empty];
        reward = {};
        reward.item_id = reward_id;
        reward.app = reward_id;
        reward.min = reward_definition.durability;
        reward.max = reward_definition.durability;
        const auto quantity = stackable ? (std::min)(remaining, 1000U) : remaining;
        reward.refine = quantity;
        remaining -= quantity;
        reward_slots.push_back(*empty);
        if (!stackable) break;
    }

    std::vector<std::pair<std::uint16_t, database::CharacterItem>> updates;
    for (std::uint16_t slot = 0U; slot < inventory.size(); ++slot) {
        const auto& before = character.inventory[slot];
        const auto& after = inventory[slot];
        if (before.item_id != after.item_id || before.app != after.app ||
            before.refine != after.refine || before.min != after.min ||
            before.max != after.max)
            updates.emplace_back(slot, after);
    }
    try {
        database::MysqlConnection database{database_config};
        database.craft_character_items(character.id, character.gold, updates);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika dismantling persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    character.inventory = inventory;

    auto removed = make_refresh_item_packet(1U, inventory_slot, {});
    if (!send_encrypted(socket, removed)) return false;
    for (const auto slot : reward_slots) {
        auto refresh = make_refresh_item_packet(1U, slot, inventory[slot], true);
        if (!send_encrypted(socket, refresh)) return false;
    }
    if (!send_client_message(socket, "Item desmontado com sucesso.", client_id))
        return false;
    auto acknowledgement = std::vector<std::byte>{request.begin(), request.end()};
    for (std::size_t offset = 12U; offset < 24U; offset += 2U)
        write_u16(0U, acknowledgement, offset);
    return send_encrypted(socket, acknowledgement);
}

[[nodiscard]] bool handle_clean_item(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        database::CharacterRecord& character, const std::uint16_t mode) {
    const auto item_slot = read_u16(request, 12U);
    if (item_slot >= 60U) return true;
    auto inventory = character.inventory;
    auto& target = inventory[item_slot];
    if (target.item_id == 0U || target.item_id >= tables.item_definitions.size()) return true;
    const auto& definition = tables.item_definitions[target.item_id];
    if (definition.can_group != 0U)
        return send_client_message(socket, "Esse item nao pode ser limpo.", client_id);

    std::optional<std::uint16_t> cleaner_slot;
    std::uint16_t cleaner_item_type{};
    const auto selection = read_u16(request, 16U);
    if (mode == 6U) {
        if (target.app == 0U)
            return send_client_message(socket, "Esse item nao possui aparencia.", client_id);
        if (target.app == target.item_id)
            return send_client_message(socket, "Esse item ja esta limpo.", client_id);
        cleaner_item_type = 517U;
    } else {
        switch (definition.quality) {
        case 0U: cleaner_item_type = 513U; break;
        case 1U:
        case 5U: cleaner_item_type = 514U; break;
        case 3U:
        case 6U: cleaner_item_type = 515U; break;
        case 7U:
            return send_client_message(socket, "Itens de cash nao podem ser limpos.", client_id);
        default:
            return send_client_message(socket, "O tipo deste item nao pode ser limpo.", client_id);
        }
    }
    for (std::uint16_t slot = 0U; slot < 60U; ++slot) {
        const auto cleaner_id = inventory[slot].item_id;
        if (cleaner_id != 0U && cleaner_id < tables.item_definitions.size() &&
            tables.item_definitions[cleaner_id].item_type == cleaner_item_type) {
            cleaner_slot = slot;
            break;
        }
    }
    if (!cleaner_slot.has_value()) {
        const auto message = mode == 6U
            ? "Voce deve possuir a Pedra Magica da Restauracao."
            : cleaner_item_type == 513U
                ? "Voce deve possuir o Vaizan Cinza correspondente."
                : cleaner_item_type == 514U
                    ? "Voce deve possuir o Vaizan Colorido correspondente."
                    : "Voce deve possuir o Vaizan Brilhante correspondente.";
        return send_client_message(socket, message, client_id);
    }

    if (mode == 6U) {
        target.app = target.item_id;
    } else if (selection == 0U) {
        target.effect_index.fill(0U);
        target.effect_value.fill(0U);
    } else if (selection == 1U) {
        std::size_t selected = 0U;
        if (target.effect_index[0] == 0U)
            selected = target.effect_index[1] == 0U ? 2U : 1U;
        target.effect_index[selected] = 0U;
        target.effect_value[selected] = 0U;
    } else if (selection == 2U) {
        const auto selected = target.effect_index[1] == 0U ? 2U : 1U;
        target.effect_index[selected] = 0U;
        target.effect_value[selected] = 0U;
    } else if (selection == 3U) {
        std::size_t selected = 2U;
        if (target.effect_index[2] == 0U)
            selected = target.effect_index[1] == 0U ? 0U : 1U;
        target.effect_index[selected] = 0U;
        target.effect_value[selected] = 0U;
    } else {
        return true;
    }

    auto& cleaner = inventory[*cleaner_slot];
    if (cleaner.refine > 1U) --cleaner.refine;
    else cleaner = {};

    std::vector<std::pair<std::uint16_t, database::CharacterItem>> updates;
    for (std::uint16_t slot = 0U; slot < inventory.size(); ++slot) {
        const auto& before = character.inventory[slot];
        const auto& after = inventory[slot];
        if (before.item_id != after.item_id || before.app != after.app ||
            before.refine != after.refine || before.effect_index != after.effect_index ||
            before.effect_value != after.effect_value)
            updates.emplace_back(slot, after);
    }
    try {
        database::MysqlConnection database{database_config};
        database.craft_character_items(character.id, character.gold, updates);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika item-cleaning persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    character.inventory = inventory;
    for (const auto& [slot, item] : updates) {
        auto refresh = make_refresh_item_packet(1U, slot, item);
        if (!send_encrypted(socket, refresh)) return false;
    }
    const auto message = mode == 6U
        ? "Aparencia do item removida."
        : selection == 0U
            ? "Adicionais do item limpos com sucesso."
            : "Adicional do item removido com sucesso.";
    if (!send_client_message(socket, message, client_id)) return false;
    auto acknowledgement = std::vector<std::byte>{request.begin(), request.end()};
    return send_encrypted(socket, acknowledgement);
}

[[nodiscard]] bool handle_make_item(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session) {
    if (request.size() < 24U || !session.entered_world ||
        !session.selected_character.has_value()) return true;
    auto& character = *session.selected_character;
    const auto item_id = read_u16(request, 12U);
    const auto requested_amount = read_u16(request, 16U);
    const auto mode = read_u16(request, 20U);
    if (mode == 1U)
        return handle_dismantle_item(socket, request, database_config,
            client_id, tables, character);
    if (mode == 3U || mode == 4U || mode == 6U)
        return handle_clean_item(socket, request, database_config,
            client_id, tables, character, mode);

    const auto recipe = std::find_if(tables.make_items.begin(), tables.make_items.end(),
        [item_id](const auto& row) { return row[0] == item_id; });
    if (recipe == tables.make_items.end())
        return send_client_message(socket, "Item nao encontrado na forja.", client_id);
    if (recipe->at(2) < 0 || recipe->at(3) < 0 || recipe->at(5) < 0 ||
        item_id == 0U || item_id >= tables.item_definitions.size()) return true;

    const auto minimum_level = static_cast<std::uint32_t>(recipe->at(2)) + 1U;
    if (minimum_level > character.level)
        return send_client_message(socket, "Voce nao possui o nivel necessario.", client_id);
    const auto requested_cost = static_cast<std::uint64_t>(recipe->at(3)) * requested_amount;
    if (requested_cost > character.gold)
        return send_client_message(socket,
            "Voce nao possui gold suficiente para fabricar este item.", client_id);

    const auto has_empty_slot = [&character](const std::uint16_t slot) {
        if (character.inventory[slot].item_id != 0U) return false;
        if (slot < 15U) return true;
        const auto bag_slot = static_cast<std::size_t>(60U + slot / 15U);
        return character.inventory[bag_slot].item_id != 0U;
    };
    const auto empty_slot = [&]() -> std::optional<std::uint16_t> {
        for (std::uint16_t slot = 0U; slot < 60U; ++slot)
            if (has_empty_slot(slot)) return slot;
        return std::nullopt;
    };
    if (!empty_slot().has_value())
        return send_client_message(socket, "Inventario cheio.", client_id);

    std::uint32_t output_amount = requested_amount;
    const auto equipment_slot = item_equip_slot(tables.item_definitions[item_id]);
    if ((equipment_slot >= 2 && equipment_slot <= 7) ||
        (equipment_slot >= 11 && equipment_slot <= 14)) output_amount = 1U;
    if (output_amount == 0U) output_amount = 1U;
    const auto crafting_cost = static_cast<std::uint64_t>(recipe->at(3)) * output_amount;
    if (crafting_cost > character.gold) return true;

    struct Ingredient final { std::uint16_t item_id; std::uint32_t amount; std::uint16_t slot; };
    std::vector<Ingredient> ingredients;
    for (const auto& row : tables.make_item_ingredients) {
        if (row[0] != recipe->at(0)) continue;
        if (row[1] <= 0 || row[1] >= static_cast<std::int32_t>(tables.item_definitions.size()) ||
            row[2] < 0) return true;
        const auto required = static_cast<std::uint64_t>(row[2]) * output_amount;
        const auto found = std::find_if(character.inventory.begin(),
            character.inventory.begin() + 60, [&character, &row](const auto& item) {
                const auto slot = static_cast<std::uint16_t>(
                    &item - character.inventory.data());
                return is_inventory_slot_unlocked(character.inventory, slot) &&
                    item.item_id == static_cast<std::uint32_t>(row[1]);
            });
        if (found == character.inventory.begin() + 60 ||
            found->refine < required) {
            const auto& name = tables.item_definitions[static_cast<std::size_t>(row[1])].name;
            const auto name_end = std::find(name.begin(), name.end(), '\0');
            const std::string item_name{name.begin(), name_end};
            return send_client_message(socket,
                "Voce precisa possuir a quantidade correta de " + item_name +
                " em um unico slot.", client_id);
        }
        const auto slot = static_cast<std::uint16_t>(
            std::distance(character.inventory.begin(), found));
        ingredients.push_back({static_cast<std::uint16_t>(row[1]),
            static_cast<std::uint32_t>(required), slot});
    }

    const auto success_divisor = recipe->at(5) / 10;
    if (success_divisor == 0)
        return send_client_message(socket, "A criacao do item falhou.", client_id);

    // The Delphi RandomRange bounds make every positive divisor successful.
    auto inventory = character.inventory;
    auto remaining_output = output_amount;
    const auto& output_definition = tables.item_definitions[item_id];
    const bool stackable = output_definition.can_group != 0U;
    if (stackable) {
        for (std::uint16_t slot = 0U; slot < 60U && remaining_output > 0U; ++slot) {
            if (!is_inventory_slot_unlocked(inventory, slot)) continue;
            auto& current = inventory[slot];
            if (current.item_id != item_id || current.refine >= 1000U) continue;
            const auto added = (std::min)(remaining_output, 1000U - current.refine);
            current.refine += added;
            remaining_output -= added;
        }
    }
    while (remaining_output > 0U) {
        std::optional<std::uint16_t> slot;
        for (std::uint16_t candidate = 0U; candidate < 60U; ++candidate) {
            if (inventory[candidate].item_id != 0U) continue;
            if (!is_inventory_slot_unlocked(inventory, candidate)) continue;
            slot = candidate;
            break;
        }
        if (!slot.has_value())
            return send_client_message(socket, "Inventario cheio.", client_id);
        auto& created = inventory[*slot];
        created = {};
        created.item_id = item_id;
        created.app = item_id;
        created.min = output_definition.durability;
        created.max = output_definition.durability;
        const auto quantity = stackable
            ? (std::min)(remaining_output, 1000U) : remaining_output;
        created.refine = quantity;
        remaining_output -= quantity;
        if (!stackable) break;
    }

    for (const auto& ingredient : ingredients) {
        auto& consumed = inventory[ingredient.slot];
        const auto slot_type = item_equip_slot(
            tables.item_definitions[ingredient.item_id]);
        if (slot_type >= 2 && slot_type <= 14) {
            consumed = {};
        } else if (consumed.refine <= ingredient.amount) {
            consumed = {};
        } else {
            consumed.refine -= ingredient.amount;
        }
    }

    std::vector<std::pair<std::uint16_t, database::CharacterItem>> updates;
    for (std::uint16_t slot = 0U; slot < inventory.size(); ++slot)
        if (inventory[slot].item_id != character.inventory[slot].item_id ||
            inventory[slot].app != character.inventory[slot].app ||
            inventory[slot].refine != character.inventory[slot].refine ||
            inventory[slot].min != character.inventory[slot].min ||
            inventory[slot].max != character.inventory[slot].max)
            updates.emplace_back(slot, inventory[slot]);
    const auto remaining_gold = character.gold - crafting_cost;
    try {
        database::MysqlConnection database{database_config};
        database.craft_character_items(character.id, remaining_gold, updates);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika crafting persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }

    character.inventory = inventory;
    character.gold = remaining_gold;
    if (!send_client_message(socket, "A criacao do item foi bem sucedida.", client_id))
        return false;
    auto money = make_refresh_money_packet(character, session.account);
    std::vector<std::byte> money_packet(money.begin(), money.end());
    if (!send_encrypted(socket, money_packet)) return false;
    for (const auto& [slot, item] : updates) {
        auto refresh = make_refresh_item_packet(1U, slot, item);
        if (!send_encrypted(socket, refresh)) return false;
    }
    return true;
}

[[nodiscard]] bool handle_delete_item(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session, ChannelRuntime& runtime) {
    if (request.size() < 20U || !session.entered_world ||
        !session.selected_character.has_value()) return true;
    const auto slot = read_u32(request, 12U);
    const auto slot_type = read_u32(request, 16U);
    auto& character = *session.selected_character;
    database::CharacterItem* item{};
    if (slot_type == 0U && slot < character.equipment.size())
        item = &character.equipment[slot];
    else if (slot_type == 1U && slot < 60U &&
        is_inventory_slot_unlocked(character.inventory,
            static_cast<std::uint16_t>(slot)))
        item = &character.inventory[slot];
    else
        return true;
    if (item->item_id == 0U || item->item_id >= tables.item_definitions.size())
        return true;

    const auto item_id = static_cast<std::uint16_t>(item->item_id);
    const auto& definition = tables.item_definitions[item_id];
    if (definition.item_type == 40U)
        return send_client_message(socket,
            "A queda de reliquias exige o sistema de mapas.", client_id);
    const auto previous_item = *item;
    *item = {};
    const std::vector<database::CharacterItemPlacement> updates{
        {static_cast<std::uint8_t>(slot_type), static_cast<std::uint16_t>(slot), *item}};
    const std::vector<std::uint16_t> buffs_to_remove =
        definition.item_type == 716U && definition.use_effect != 0U
            ? std::vector<std::uint16_t>{definition.use_effect}
            : std::vector<std::uint16_t>{};
    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(character.id, character.gold, updates,
            buffs_to_remove);
    } catch (const std::exception& error) {
        *item = previous_item;
        OutputDebugStringA((std::string{"Aika item deletion persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }

    auto refresh = make_refresh_item_packet(static_cast<std::uint16_t>(slot_type),
        static_cast<std::uint16_t>(slot), {});
    if (!send_encrypted(socket, refresh)) return false;
    const auto name_end = std::find(definition.name.begin(), definition.name.end(), '\0');
    const std::string item_name{definition.name.begin(), name_end};
    if (!send_client_message(socket, "O item [" + item_name + "] foi deletado.",
            client_id)) return false;

    if (definition.item_type == 716U && definition.use_effect != 0U) {
        for (auto& buff : character.buffs)
            if (buff[0] == definition.use_effect) buff = {};
        if (!runtime.refresh_buffs(session, tables)) return false;
        auto hp_mp = make_current_hp_mp_packet(character, client_id, tables);
        if (!send_encrypted(socket, hp_mp)) return false;
        auto status = make_refresh_status_packet(character, tables);
        if (!send_encrypted(socket, status)) return false;
        auto points = make_refresh_points_packet(character);
        if (!send_encrypted(socket, points)) return false;
    }
    if (slot_type == 0U) {
        if (!runtime.refresh_equipment_status(session, tables)) return false;
        return runtime.refresh_player_spawn(session, tables);
    }
    return true;
}

[[nodiscard]] bool handle_group_item(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const data::GameTables& tables, GameSession& session) {
    if (request.size() < 20U || !session.entered_world ||
        !session.selected_character.has_value()) return true;
    const auto source_slot = read_u32(request, 12U);
    const auto destination_slot = read_u32(request, 16U);
    if (source_slot >= 60U || destination_slot >= 60U ||
        source_slot == destination_slot) return true;
    auto& character = *session.selected_character;
    if (!is_inventory_slot_unlocked(character.inventory,
            static_cast<std::uint16_t>(source_slot)) ||
        !is_inventory_slot_unlocked(character.inventory,
            static_cast<std::uint16_t>(destination_slot))) return true;
    auto& source = character.inventory[source_slot];
    auto& destination = character.inventory[destination_slot];
    if (source.item_id == 0U || source.item_id != destination.item_id ||
        source.item_id >= tables.item_definitions.size() ||
        tables.item_definitions[source.item_id].can_group == 0U ||
        source.refine == 0U || destination.refine == 0U) return true;

    constexpr std::uint32_t maximum_stack = 1000U;
    if (source.refine == 0U || destination.refine == 0U ||
        source.refine > maximum_stack || destination.refine > maximum_stack)
        return true;
    const auto combined = source.refine + destination.refine;
    auto updated_source = source;
    auto updated_destination = destination;
    if (combined <= maximum_stack) {
        updated_destination.refine = combined;
        updated_source = {};
    } else {
        updated_destination.refine = maximum_stack;
        updated_source.refine = combined - maximum_stack;
    }
    const std::vector<database::CharacterItemPlacement> updates{
        {1U, static_cast<std::uint16_t>(source_slot), updated_source},
        {1U, static_cast<std::uint16_t>(destination_slot), updated_destination}};
    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(character.id, character.gold, updates);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika item-stack merge persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    source = updated_source;
    destination = updated_destination;
    auto source_refresh = make_refresh_item_packet(1U,
        static_cast<std::uint16_t>(source_slot), source);
    if (!send_encrypted(socket, source_refresh)) return false;
    auto destination_refresh = make_refresh_item_packet(1U,
        static_cast<std::uint16_t>(destination_slot), destination);
    return send_encrypted(socket, destination_refresh);
}

[[nodiscard]] bool handle_ungroup_item(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const data::GameTables& tables, GameSession& session,
        const std::uint16_t client_id) {
    if (request.size() < 24U || !session.entered_world ||
        !session.selected_character.has_value()) return true;
    const auto source_slot = read_u32(request, 12U);
    const auto quantity = read_u32(request, 16U);
    const auto slot_type = read_u32(request, 20U);
    if (slot_type == 0U || slot_type == 5U || slot_type == 6U) return true;
    if (slot_type != 1U || source_slot >= 60U || quantity == 0U ||
        quantity > (std::numeric_limits<std::uint16_t>::max)()) return true;
    auto& character = *session.selected_character;
    if (!is_inventory_slot_unlocked(character.inventory,
            static_cast<std::uint16_t>(source_slot))) return true;
    auto& source = character.inventory[source_slot];
    if (source.item_id == 0U || source.item_id >= tables.item_definitions.size() ||
        tables.item_definitions[source.item_id].can_group == 0U ||
        tables.item_definitions[source.item_id].expires != 0U ||
        quantity >= source.refine) return true;

    std::optional<std::uint16_t> destination_slot;
    for (std::uint16_t slot = 0U; slot < 60U; ++slot) {
        if (character.inventory[slot].item_id != 0U) continue;
        if (!is_inventory_slot_unlocked(character.inventory, slot)) continue;
        destination_slot = slot;
        break;
    }
    if (!destination_slot.has_value())
        return send_client_message(socket, "Inventario cheio.", client_id);

    auto updated_source = source;
    auto updated_destination = source;
    updated_source.refine -= quantity;
    updated_destination.refine = quantity;
    const std::vector<database::CharacterItemPlacement> updates{
        {1U, static_cast<std::uint16_t>(source_slot), updated_source},
        {1U, *destination_slot, updated_destination}};
    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(character.id, character.gold, updates);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika item-stack split persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    source = updated_source;
    character.inventory[*destination_slot] = updated_destination;
    auto source_refresh = make_refresh_item_packet(1U,
        static_cast<std::uint16_t>(source_slot), source);
    if (!send_encrypted(socket, source_refresh)) return false;
    auto destination_refresh = make_refresh_item_packet(1U, *destination_slot,
        character.inventory[*destination_slot]);
    return send_encrypted(socket, destination_refresh);
}

[[nodiscard]] bool handle_repair_item(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const data::GameTables& tables, GameSession& session,
        const std::uint16_t client_id) {
    if (request.size() < 24U || !session.entered_world ||
        !session.selected_character.has_value()) return true;
    constexpr std::uint32_t inventory_type = 1U;
    constexpr std::uint32_t item_use_type = 9U;
    auto& character = *session.selected_character;
    if (read_u32(request, 12U) != item_use_type) return true;
    const auto repair_slot = read_u32(request, 16U);
    if (repair_slot >= 60U) return true;
    const auto repair_item_id = character.inventory[repair_slot].item_id;
    if (repair_item_id == 0U || repair_item_id >= tables.item_definitions.size())
        return true;
    const auto& repair_definition = tables.item_definitions[repair_item_id];
    if (repair_definition.item_type != 708U && repair_definition.item_type != 709U)
        return true;

    const auto target_selector = read_u32(request, 20U);
    std::uint32_t target_slot{};
    std::uint32_t target_type{};
    database::CharacterItem* target{};
    if (target_selector > 16U) {
        target_type = inventory_type;
        target_slot = target_selector - 16U;
        if (target_slot < character.inventory.size())
            target = &character.inventory[target_slot];
    } else {
        target_type = 0U;
        target_slot = target_selector;
        if (target_slot < character.equipment.size())
            target = &character.equipment[target_slot];
    }
    const auto previous_repair_item = character.inventory[repair_slot];
    const auto previous_target_item = target != nullptr
        ? std::optional<database::CharacterItem>{*target} : std::nullopt;
    bool target_changed = false;
    if (target != nullptr && target->item_id > 0U &&
        target->item_id < tables.item_definitions.size()) {
        const auto equip_slot = item_equip_slot(
            tables.item_definitions[target->item_id]);
        const bool repairable = repair_definition.item_type == 708U
            ? equip_slot == 6U
            : (equip_slot == 2U || equip_slot == 3U || equip_slot == 4U ||
               equip_slot == 5U || equip_slot == 7U);
        if (repairable) {
            target->min = target->max;
            target_changed = true;
        }
    }

    auto& repair_item = character.inventory[repair_slot];
    if (repair_item.refine > 1U) --repair_item.refine;
    else repair_item = {};
    std::vector<database::CharacterItemPlacement> updates;
    updates.push_back({1U, static_cast<std::uint16_t>(repair_slot), repair_item});
    if (target_changed && !(target_type == inventory_type &&
            target_slot == repair_slot))
        updates.push_back({static_cast<std::uint8_t>(target_type),
            static_cast<std::uint16_t>(target_slot), *target});
    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(character.id, character.gold, updates);
    } catch (const std::exception& error) {
        repair_item = previous_repair_item;
        if (target_changed && previous_target_item.has_value())
            *target = *previous_target_item;
        OutputDebugStringA((std::string{"Aika repair-item persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }

    if (target_changed && !(target_type == inventory_type &&
            target_slot == repair_slot)) {
        auto target_refresh = make_refresh_item_packet(
            static_cast<std::uint16_t>(target_type),
            static_cast<std::uint16_t>(target_slot), *target);
        if (!send_encrypted(socket, target_refresh)) return false;
    }
    if (!send_client_message(socket, "Item reparado com sucesso.", client_id))
        return false;
    auto consumed_refresh = make_refresh_item_packet(1U,
        static_cast<std::uint16_t>(repair_slot), repair_item);
    if (!send_encrypted(socket, consumed_refresh)) return false;
    if (target_changed && target_type == 0U) {
        auto status = make_refresh_status_packet(character, tables);
        if (!send_encrypted(socket, status)) return false;
        auto points = make_refresh_points_packet(character);
        if (!send_encrypted(socket, points)) return false;
        auto hp_mp = make_current_hp_mp_packet(character, client_id, tables);
        return send_encrypted(socket, hp_mp);
    }
    return true;
}

[[nodiscard]] bool handle_use_hp_mp_potion(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session, ChannelRuntime& runtime) {
    if (request.size() < 24U || !session.entered_world ||
        !session.selected_character.has_value() ||
        read_u32(request, 12U) != 1U) return true;
    auto& character = *session.selected_character;
    if (character.current_hp == 0U) return true;
    const auto slot = read_u32(request, 16U);
    if (slot >= 60U) return true;
    const auto& item = character.inventory[slot];
    if (item.item_id == 0U || item.item_id >= tables.item_definitions.size())
        return true;
    const auto& definition = tables.item_definitions[item.item_id];
    if (definition.item_type != 29U && definition.item_type != 700U &&
        definition.item_type != 701U && definition.item_type != 800U) return true;
    if (session.account.account_type != 5U && definition.level > character.level)
        return true;

    const auto [max_hp, max_mp] = estimate_max_hp_mp(character, tables);
    auto updated_hp = character.current_hp;
    auto updated_mp = character.current_mp;
    const auto restore = [&definition](const std::uint32_t current,
            const std::uint32_t maximum) {
        return static_cast<std::uint32_t>((std::min)(
            static_cast<std::uint64_t>(current) + definition.use_effect,
            static_cast<std::uint64_t>(maximum)));
    };
    if (definition.item_type == 29U || definition.item_type == 700U ||
        definition.item_type == 800U)
        updated_hp = restore(updated_hp, max_hp);
    if (definition.item_type == 29U || definition.item_type == 701U ||
        definition.item_type == 800U)
        updated_mp = restore(updated_mp, max_mp);

    auto updated_item = item;
    if (updated_item.refine > 1U) --updated_item.refine;
    else updated_item = {};
    const std::vector<database::CharacterItemPlacement> updates{
        {1U, static_cast<std::uint16_t>(slot), updated_item}};
    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(character.id, character.gold, updates, {},
            std::pair{updated_hp, updated_mp});
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika potion persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    character.current_hp = updated_hp;
    character.current_mp = updated_mp;
    character.inventory[slot] = updated_item;

    auto hp_mp = make_current_hp_mp_packet(character, client_id, tables, true);
    if (!runtime.send_to_visible(session, hp_mp)) return false;
    auto refresh = make_refresh_item_packet(1U,
        static_cast<std::uint16_t>(slot), updated_item);
    return send_encrypted(socket, refresh);
}

[[nodiscard]] bool handle_use_gold_coin(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session) {
    if (request.size() < 24U || !session.entered_world ||
        !session.selected_character.has_value() ||
        read_u32(request, 12U) != 1U) return true;
    auto& character = *session.selected_character;
    const auto slot = read_u32(request, 16U);
    if (slot >= 60U) return true;
    const auto& item = character.inventory[slot];
    if (item.item_id == 0U || item.item_id >= tables.item_definitions.size())
        return true;
    const auto& definition = tables.item_definitions[item.item_id];
    std::uint64_t amount{};
    if (definition.item_type == 234U)
        amount = definition.sell_price;
    else if (definition.item_type == 717U)
        amount = 950'000'000U;
    else
        return true;
    if (session.account.account_type != 5U && definition.level > character.level)
        return true;

    auto updated_item = item;
    if (updated_item.refine > 1U) --updated_item.refine;
    else updated_item = {};
    const auto updated_gold = character.gold + amount;
    const std::vector<database::CharacterItemPlacement> updates{
        {1U, static_cast<std::uint16_t>(slot), updated_item}};
    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(character.id, updated_gold, updates);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika gold-coin persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    character.gold = updated_gold;
    character.inventory[slot] = updated_item;
    auto money = make_refresh_money_packet(character, session.account);
    std::vector<std::byte> money_packet(money.begin(), money.end());
    if (!send_encrypted(socket, money_packet)) return false;
    if (!send_client_message(socket,
            "Voce recebeu o valor de [" + std::to_string(amount) + "] em gold.",
            client_id)) return false;
    auto refresh = make_refresh_item_packet(1U,
        static_cast<std::uint16_t>(slot), updated_item);
    return send_encrypted(socket, refresh);
}

[[nodiscard]] bool handle_use_cash_coin(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const data::GameTables& tables, GameSession& session) {
    if (request.size() < 24U || !session.entered_world ||
        !session.selected_character.has_value() || read_u32(request, 12U) != 1U)
        return true;
    const auto slot = read_u32(request, 16U);
    if (slot >= 60U) return true;
    auto& character = *session.selected_character;
    const auto& item = character.inventory[slot];
    if (item.item_id == 0U || item.item_id >= tables.item_definitions.size())
        return true;
    const auto& definition = tables.item_definitions[item.item_id];
    if (definition.item_type != 239U ||
        (session.account.account_type != 5U && definition.level > character.level))
        return true;

    const auto updated_cash = static_cast<std::uint32_t>(
        session.account.cash + definition.use_effect);
    auto updated_item = item;
    if (updated_item.refine > 1U) --updated_item.refine;
    else updated_item = {};
    const std::vector<database::CharacterItemPlacement> updates{
        {1U, static_cast<std::uint16_t>(slot), updated_item}};
    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(character.id, character.gold, updates, {},
            std::nullopt, std::pair{session.account.id, updated_cash});
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika cash-coin persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    session.account.cash = updated_cash;
    character.inventory[slot] = updated_item;
    std::vector<std::byte> cash_packet(16U);
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(cash_packet.size());
    header.client_index = 0U;
    header.opcode = 0x0139U;
    const auto encoded = protocol::encode_header(header);
    std::copy(encoded.begin(), encoded.end(), cash_packet.begin());
    write_u32(updated_cash, cash_packet, 12U);
    if (!send_encrypted(socket, cash_packet)) return false;
    auto refresh = make_refresh_item_packet(1U,
        static_cast<std::uint16_t>(slot), updated_item);
    return send_encrypted(socket, refresh);
}

void apply_character_level_award(database::CharacterRecord& character,
        const std::uint16_t increment,
        std::vector<std::pair<std::uint16_t, std::uint16_t>>& event_rewards) {
    if (character.level <= 50U && character.level + increment >= 51U)
        ++character.class_info;
    character.level = static_cast<std::uint16_t>(character.level + increment);
    ++character.skill_points;
    if (character.level > 50U)
        character.attributes[5U] = static_cast<std::uint16_t>(
            character.attributes[5U] + 2U);
    if (character.level == 51U || character.level == 61U ||
        character.level == 71U || character.level == 81U) {
        character.skill_points = static_cast<std::uint16_t>(
            character.skill_points + 12U);
        character.attributes[5U] = static_cast<std::uint16_t>(
            character.attributes[5U] + 10U);
    }
    if (character.level != 50U) return;

    std::uint16_t class_reward{};
    switch (character.class_info) {
    case 1U: case 2U: class_reward = 8849U; break;
    case 11U: case 12U: class_reward = 8850U; break;
    case 21U: case 22U: class_reward = 8851U; break;
    case 31U: case 32U: class_reward = 8852U; break;
    case 41U: case 42U: class_reward = 8853U; break;
    case 51U: case 52U: class_reward = 8854U; break;
    default: break;
    }
    if (class_reward != 0U)
        event_rewards.emplace_back(class_reward, std::uint16_t{1U});
    event_rewards.emplace_back(std::uint16_t{5640U}, std::uint16_t{1U});
    static thread_local std::mt19937 random_engine{std::random_device{}()};
    constexpr std::array<std::uint64_t, 4U> gold_rewards{
        10'000U, 100'000U, 1'000'000U, 10'000'000U};
    const auto reward = std::uniform_int_distribution<std::size_t>{
        0U, gold_rewards.size() - 1U}(random_engine);
    character.gold += gold_rewards[reward];
}

[[nodiscard]] bool handle_use_exp_item(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session) {
    if (request.size() < 24U || !session.entered_world ||
        !session.selected_character.has_value() || read_u32(request, 12U) != 1U)
        return true;
    auto& character = *session.selected_character;
    if (character.current_hp == 0U) return true;
    const auto slot = read_u32(request, 16U);
    if (slot >= 60U) return true;
    const auto& item = character.inventory[slot];
    if (item.item_id == 0U || item.item_id >= tables.item_definitions.size())
        return true;
    const auto& definition = tables.item_definitions[item.item_id];
    if ((definition.item_type != 404U && definition.item_type != 704U) ||
        (session.account.account_type != 5U && definition.level > character.level))
        return true;
    auto updated_item = item;
    if (updated_item.refine > 1U) --updated_item.refine;
    else updated_item = {};

    auto updated_character = character;
    bool leveled_up = false;
    bool progression_changed = false;
    bool refresh_level_packet = false;
    bool refresh_level_stats = false;
    std::vector<std::pair<std::uint16_t, std::uint16_t>> event_rewards;
    if (definition.item_type == 404U && character.level != 90U &&
        character.level > 0U && character.level < tables.experience_table.size()) {
        const auto current_level = static_cast<std::size_t>(character.level);
        const auto previous_threshold = tables.experience_table[current_level - 1U];
        const auto current_threshold = tables.experience_table[current_level];
        if (current_threshold >= previous_threshold) {
            const auto level_delta = current_threshold - previous_threshold;
            const auto gain = static_cast<std::uint64_t>(std::nearbyint(
                static_cast<double>(level_delta) * definition.use_effect / 1000.0));
            progression_changed = true;
            refresh_level_packet = true;
            auto experience = character.experience;
            experience = gain > (std::numeric_limits<std::uint64_t>::max)() - experience
                ? (std::numeric_limits<std::uint64_t>::max)() : experience + gain;
            const auto level_cap = static_cast<std::uint16_t>((std::min<std::size_t>)(
                90U, tables.experience_table.size() - 1U));
            while (updated_character.level < level_cap &&
                updated_character.level < tables.experience_table.size() &&
                experience > tables.experience_table[updated_character.level]) {
                apply_character_level_award(updated_character, 1U, event_rewards);
                leveled_up = true;
            }
            if (updated_character.level == level_cap &&
                experience > tables.experience_table[level_cap])
                experience = tables.experience_table[level_cap];
            updated_character.experience = experience;
            refresh_level_stats = leveled_up;
            if (leveled_up) {
                const auto [max_hp, max_mp] = estimate_max_hp_mp(updated_character, tables);
                updated_character.current_hp = max_hp;
                updated_character.current_mp = max_mp;
            }
        }
    } else if (definition.item_type == 704U) {
        if (definition.use_effect == 1U) {
            if (character.level > 0U && !tables.experience_table.empty()) {
                progression_changed = true;
                refresh_level_packet = true;
                const auto target_index = static_cast<std::size_t>(character.level) +
                    definition.use_effect * 50U - 1U;
                std::uint64_t experience{};
                if (target_index < tables.experience_table.size()) {
                    experience = tables.experience_table[target_index] ==
                            (std::numeric_limits<std::uint64_t>::max)()
                        ? tables.experience_table[target_index]
                        : tables.experience_table[target_index] + 1U;
                } else {
                    // Delphi's fallback is High(ExpList), which is its final index.
                    experience = tables.experience_table.size() - 1U;
                }
                const auto level_cap = static_cast<std::uint16_t>((std::min<std::size_t>)(
                    90U, tables.experience_table.size() - 1U));
                while (updated_character.level < level_cap &&
                    experience > tables.experience_table[updated_character.level]) {
                    apply_character_level_award(updated_character, 1U, event_rewards);
                    leveled_up = true;
                }
                if (updated_character.level == level_cap &&
                    experience > tables.experience_table[level_cap])
                    experience = tables.experience_table[level_cap];
                updated_character.experience = experience;
                refresh_level_stats = leveled_up;
            }
        } else if (character.level < 90U) {
            apply_character_level_award(updated_character, definition.use_effect,
                event_rewards);
            leveled_up = true;
            progression_changed = true;
            refresh_level_packet = true;
            refresh_level_stats = true;
        }
        if (leveled_up) {
            const auto [max_hp, max_mp] = estimate_max_hp_mp(updated_character, tables);
            updated_character.current_hp = max_hp;
            updated_character.current_mp = max_mp;
        }
    }

    const std::vector<database::CharacterItemPlacement> updates{
        {1U, static_cast<std::uint16_t>(slot), updated_item}};
    const auto progression = progression_changed
        ? std::optional<database::CharacterProgression>{database::CharacterProgression{
            .class_info = updated_character.class_info,
            .level = updated_character.level,
            .skill_points = updated_character.skill_points,
            .attributes = updated_character.attributes,
            .experience = updated_character.experience,
            .gold = updated_character.gold,
            .current_hp = updated_character.current_hp,
            .current_mp = updated_character.current_mp}}
        : std::nullopt;
    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(character.id, updated_character.gold, updates,
            {}, std::nullopt, std::nullopt, std::nullopt, progression, event_rewards);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika experience-item persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    character = updated_character;
    character.inventory[slot] = updated_item;
    if (refresh_level_packet) {
        auto level = make_refresh_level_packet(character, client_id);
        if (!send_encrypted(socket, level)) return false;
    }
    if (refresh_level_stats) {
        auto points = make_refresh_points_packet(character);
        if (!send_encrypted(socket, points)) return false;
        auto status = make_refresh_status_packet(character, tables);
        if (!send_encrypted(socket, status)) return false;
        auto hp_mp = make_current_hp_mp_packet(character, client_id, tables, true);
        if (!send_encrypted(socket, hp_mp)) return false;
        auto money = make_refresh_money_packet(character, session.account);
        std::vector<std::byte> money_packet(money.begin(), money.end());
        if (!event_rewards.empty() && !send_encrypted(socket, money_packet)) return false;
        if (character.level == 50U &&
            !send_client_message(socket, "Voce recebeu uma recompensa de gold!", client_id))
            return false;
    }
    auto refresh = make_refresh_item_packet(1U,
        static_cast<std::uint16_t>(slot), updated_item);
    return send_encrypted(socket, refresh);
}

[[nodiscard]] bool handle_receive_event_items(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session) {
    if (request.size() < 12U || !session.entered_world ||
        !session.selected_character.has_value()) return true;
    const auto signal = [&socket, client_id]() {
        std::vector<std::byte> packet(12U);
        protocol::PacketHeader header{};
        header.size = static_cast<std::uint16_t>(packet.size());
        header.client_index = client_id;
        header.opcode = receive_event_item_opcode;
        const auto encoded = protocol::encode_header(header);
        std::copy(encoded.begin(), encoded.end(), packet.begin());
        return send_encrypted(socket, packet);
    };

    const auto& character = *session.selected_character;
    const auto available_slots = empty_unlocked_inventory_slots(character.inventory);
    if (available_slots == 0U) {
        if (!send_client_message(socket, "Inventario cheio.", client_id)) return false;
        return signal();
    }

    try {
        database::MysqlConnection database{database_config};
        const auto pending = database.load_character_event_items(character.id);
        const auto now = static_cast<std::uint64_t>(std::time(nullptr));
        const bool diary_available = character.last_diary_event == 0U ||
            (now >= character.last_diary_event &&
                now - character.last_diary_event >= 24U * 60U * 60U);
        std::vector<database::EventItemRecord> rewards = pending;
        if (diary_available)
            rewards.push_back({std::uint16_t{10467U}, std::uint16_t{1U}});
        if (rewards.empty()) {
            if (!send_client_message(socket,
                    "Nao existem itens de evento para receber.", client_id)) return false;
            return signal();
        }

        const auto claim_count = (std::min)(available_slots, rewards.size());
        auto updated_character = character;
        std::vector<std::pair<std::uint16_t, std::uint16_t>> claims;
        std::vector<std::pair<std::uint16_t, std::uint16_t>> queued_rewards;
        std::unordered_set<std::uint16_t> changed_slots;
        bool diary_placed{};
        const auto find_empty_slot = [&updated_character]()
                -> std::optional<std::uint16_t> {
            for (std::uint16_t slot = 0U; slot < 60U; ++slot)
                if (is_inventory_slot_unlocked(updated_character.inventory, slot) &&
                    updated_character.inventory[slot].item_id == 0U)
                    return slot;
            return std::nullopt;
        };

        for (std::size_t index = 0U; index < claim_count; ++index) {
            const auto inventory_before_reward = updated_character.inventory;
            const auto changed_before_reward = changed_slots;
            const auto reward = rewards[index];
            if (reward.item_id == 0U || reward.item_id >= tables.item_definitions.size())
                continue;
            const auto& definition = tables.item_definitions[reward.item_id];
            auto remaining = static_cast<std::uint32_t>(reward.quantity);
            bool placed{};
            if (definition.can_group != 0U) {
                for (std::uint16_t slot = 0U; slot < 60U && remaining > 0U; ++slot) {
                    if (!is_inventory_slot_unlocked(updated_character.inventory, slot))
                        continue;
                    auto& existing = updated_character.inventory[slot];
                    if (existing.item_id != reward.item_id || existing.refine >= 1000U)
                        continue;
                    const auto added = (std::min)(remaining, 1000U - existing.refine);
                    existing.refine += added;
                    remaining -= added;
                    changed_slots.insert(slot);
                    placed = true;
                }
            }
            if (!definition.can_group || reward.quantity == 0U) remaining = 0U;
            while (remaining > 0U || !placed) {
                const auto slot = find_empty_slot();
                if (!slot.has_value()) break;
                database::CharacterItem item{};
                item.item_id = reward.item_id;
                item.app = reward.item_id;
                item.min = definition.durability;
                item.max = definition.durability;
                item.refine = definition.can_group != 0U
                    ? (reward.quantity == 0U ? 0U : (std::min)(remaining, 1000U))
                    : reward.quantity;
                updated_character.inventory[*slot] = item;
                changed_slots.insert(*slot);
                placed = true;
                if (definition.can_group == 0U || reward.quantity == 0U) break;
                remaining -= item.refine;
            }
            if (definition.can_group != 0U && remaining > 0U) {
                // Keep an oversized reward queued if its full stack cannot fit.
                updated_character.inventory = inventory_before_reward;
                changed_slots = changed_before_reward;
                break;
            }
            // Existing event rows are removed only after their item placement
            // has been planned for the same database transaction.
            if (index < pending.size())
                claims.emplace_back(reward.item_id, reward.quantity);
            else
                diary_placed = true;
        }

        std::optional<std::uint64_t> diary_time;
        if (diary_available) {
            updated_character.last_diary_event = now;
            diary_time = now;
            if (!diary_placed)
                queued_rewards.emplace_back(std::uint16_t{10467U}, std::uint16_t{1U});
        }
        std::vector<database::CharacterItemPlacement> updates;
        updates.reserve(changed_slots.size());
        for (const auto slot : changed_slots)
            updates.push_back({1U, slot, updated_character.inventory[slot]});
        database.save_character_items(character.id, character.gold, updates, {},
            std::nullopt, std::nullopt, std::nullopt, std::nullopt,
            queued_rewards, claims, diary_time);
        session.selected_character = updated_character;
        for (const auto slot : changed_slots) {
            auto refresh = make_refresh_item_packet(1U, slot,
                updated_character.inventory[slot]);
            if (!send_encrypted(socket, refresh)) return false;
        }
        if (!send_client_message(socket,
                "Nao existem mais itens de evento para receber.", client_id)) return false;
        return signal();
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika event-item claim failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
}

[[nodiscard]] bool handle_use_recipe_item(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session) {
    if (request.size() < 24U || !session.entered_world ||
        !session.selected_character.has_value() || read_u32(request, 12U) != 1U)
        return true;
    const auto requested_slot = read_u32(request, 16U);
    if (requested_slot >= 60U) return true;
    auto& character = *session.selected_character;
    const auto recipe_item_id = character.inventory[requested_slot].item_id;
    if (recipe_item_id == 0U || recipe_item_id >= tables.item_definitions.size() ||
        tables.item_definitions[recipe_item_id].item_type != 205U) return true;
    const auto& recipe_item = tables.item_definitions[recipe_item_id];
    if (session.account.account_type != 5U && recipe_item.level > character.level)
        return true;

    const auto recipe_it = std::find_if(tables.recipes.begin(), tables.recipes.end(),
        [recipe_item_id](const data::RecipeDefinition& candidate) {
            return candidate.recipe_item_id == recipe_item_id;
        });
    if (recipe_it == tables.recipes.end())
        return send_client_message(socket,
            "A receita nao existe no banco de dados.", client_id);
    const auto& recipe = *recipe_it;
    if (session.account.account_type != 5U && recipe.min_level > character.level)
        return send_client_message(socket, "Seu nivel nao e suficiente.", client_id);

    std::array<std::uint16_t, 12U> required_items = recipe.required_item_ids;
    for (auto& item_id : required_items)
        if (item_id == 4202U) item_id = 4204U;
    for (std::size_t ingredient = 0U; ingredient < required_items.size(); ++ingredient) {
        const auto item_id = required_items[ingredient];
        if (item_id == 0U) continue;
        if (item_id >= tables.item_definitions.size())
            return send_client_message(socket,
                "A receita contem um material invalido.", client_id);
        const auto found = std::find_if(character.inventory.begin(),
            character.inventory.begin() + 60, [&character, item_id](
                const database::CharacterItem& item) {
                const auto slot = static_cast<std::uint16_t>(
                    &item - character.inventory.data());
                return is_inventory_slot_unlocked(character.inventory, slot) &&
                    item.item_id == item_id;
            });
        const auto name_end = std::find(tables.item_definitions[item_id].name.begin(),
            tables.item_definitions[item_id].name.end(), '\0');
        const std::string item_name{tables.item_definitions[item_id].name.begin(), name_end};
        if (found == character.inventory.begin() + 60)
            return send_client_message(socket,
                "Voce nao possui [" + item_name + "].", client_id);
        if (found->refine < recipe.required_amounts[ingredient])
            return send_client_message(socket,
                "Voce precisa de " + std::to_string(recipe.required_amounts[ingredient]) +
                " do item [" + item_name + "]. Separe a quantidade correta em apenas UM slot.",
                client_id);
    }

    const auto empty_slot = first_empty_inventory_slot(character.inventory);
    if (!empty_slot.has_value())
        return send_client_message(socket, "Seu inventario esta cheio.", client_id);

    auto updated_character = character;
    const bool success = recipe.success_rate / 10U > 0U;
    if (success) {
        if (recipe.reward >= tables.item_definitions.size())
            return send_client_message(socket,
                "A receita contem uma recompensa invalida.", client_id);
        const auto& reward_definition = tables.item_definitions[recipe.reward];
        auto remaining = static_cast<std::uint32_t>(recipe.reward_amount);
        bool placed{};
        if (reward_definition.can_group != 0U) {
            for (std::uint16_t slot = 0U; slot < 60U && remaining > 0U; ++slot) {
                if (!is_inventory_slot_unlocked(updated_character.inventory, slot))
                    continue;
                auto& existing = updated_character.inventory[slot];
                if (existing.item_id != recipe.reward || existing.refine >= 1000U) continue;
                const auto added = (std::min)(remaining, 1000U - existing.refine);
                existing.refine += added;
                remaining -= added;
                placed = true;
            }
        }
        if (!reward_definition.can_group || recipe.reward_amount == 0U) remaining = 0U;
        while (remaining > 0U || !placed) {
            std::optional<std::uint16_t> slot;
            for (std::uint16_t candidate = 0U; candidate < 60U; ++candidate)
                if (is_inventory_slot_unlocked(updated_character.inventory, candidate) &&
                    updated_character.inventory[candidate].item_id == 0U) {
                    slot = candidate;
                    break;
                }
            if (!slot.has_value())
                return send_client_message(socket, "Seu inventario esta cheio.", client_id);
            database::CharacterItem item{};
            item.item_id = recipe.reward;
            item.app = recipe.reward;
            item.min = reward_definition.durability;
            item.max = reward_definition.durability;
            item.refine = reward_definition.can_group != 0U
                ? (recipe.reward_amount == 0U ? 0U : (std::min)(remaining, 1000U))
                : recipe.reward_amount;
            updated_character.inventory[*slot] = item;
            placed = true;
            if (reward_definition.can_group == 0U || recipe.reward_amount == 0U) break;
            remaining -= item.refine;
        }

        for (std::size_t ingredient = 0U; ingredient < required_items.size(); ++ingredient) {
            const auto item_id = required_items[ingredient];
            if (item_id == 0U) continue;
            const auto found = std::find_if(updated_character.inventory.begin(),
                updated_character.inventory.begin() + 60,
                [&updated_character, item_id](const database::CharacterItem& item) {
                    const auto slot = static_cast<std::uint16_t>(
                        &item - updated_character.inventory.data());
                    return is_inventory_slot_unlocked(updated_character.inventory, slot) &&
                        item.item_id == item_id;
                });
            if (found == updated_character.inventory.begin() + 60) continue;
            const auto amount = recipe.required_amounts[ingredient];
            const auto equipment_slot = amount < tables.item_definitions.size()
                ? item_equip_slot(tables.item_definitions[amount]) : 0;
            if (equipment_slot >= 2 && equipment_slot <= 14) {
                *found = {};
            } else if (found->refine > amount) {
                found->refine -= amount;
            } else {
                *found = {};
            }
        }
    }
    auto& consumed_recipe = updated_character.inventory[requested_slot];
    if (consumed_recipe.item_id != 0U) {
        if (consumed_recipe.refine > 1U) --consumed_recipe.refine;
        else consumed_recipe = {};
    }

    std::vector<database::CharacterItemPlacement> updates;
    for (std::uint16_t slot = 0U; slot < updated_character.inventory.size(); ++slot) {
        const auto& before = character.inventory[slot];
        const auto& after = updated_character.inventory[slot];
        if (before.item_id != after.item_id || before.app != after.app ||
            before.refine != after.refine || before.min != after.min ||
            before.max != after.max || before.identific != after.identific ||
            before.effect_index != after.effect_index ||
            before.effect_value != after.effect_value || before.time != after.time)
            updates.push_back({1U, slot, after});
    }
    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(character.id, character.gold, updates);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika recipe-item persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    character.inventory = updated_character.inventory;
    if (!send_client_message(socket, success
            ? "Receita bem sucedida." : "Receita falhou e foi perdida.", client_id))
        return false;
    for (const auto& update : updates) {
        auto refresh = make_refresh_item_packet(1U, update.slot, update.item);
        if (!send_encrypted(socket, refresh)) return false;
    }
    return true;
}

[[nodiscard]] bool handle_use_equipment_set_box(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session) {
    if (request.size() < 24U || !session.entered_world ||
        !session.selected_character.has_value() || read_u32(request, 12U) != 1U)
        return true;
    auto& character = *session.selected_character;
    const auto slot = read_u32(request, 16U);
    if (slot >= 60U) return true;
    const auto& box = character.inventory[slot];
    if (box.item_id == 0U || box.item_id >= tables.item_definitions.size()) return true;
    const auto& box_definition = tables.item_definitions[box.item_id];
    const auto effect = box_definition.use_effect;
    const bool supported_effect = effect == 1089U || effect == 1U || effect == 39U ||
        effect == 41U || (effect >= 42U && effect <= 45U) ||
        (effect >= 137U && effect <= 142U) || effect == 5289U ||
        effect == 1133U || (effect >= 1138U && effect <= 1145U) ||
        (effect >= 1493U && effect <= 1500U) || effect == 1105U ||
        effect == 1854U || effect == 1856U || effect == 1857U || effect == 18855U;
    const bool supported_item_type = box_definition.item_type == 714U ||
        (box_definition.item_type == 705U && effect == 1089U);
    if (!supported_item_type || !supported_effect ||
        (session.account.account_type != 5U && box_definition.level > character.level))
        return true;

    if (effect >= 1493U && effect <= 1500U) {
        const auto empty_count = empty_unlocked_inventory_slots(character.inventory);
        if (empty_count == 0)
            return send_client_message(socket, "Invent\xE1rio cheio.", client_id);
        const auto reward_id = static_cast<std::uint32_t>(effect + 14427U);
        if (reward_id >= tables.item_definitions.size()) return true;
        std::optional<std::uint16_t> reward_slot;
        auto updated_inventory = character.inventory;
        const auto& reward_definition = tables.item_definitions[reward_id];
        if (reward_definition.can_group != 0U) {
            for (std::uint16_t candidate = 0U; candidate < 60U; ++candidate) {
                auto& current = updated_inventory[candidate];
                if (!is_inventory_slot_unlocked(updated_inventory, candidate) ||
                    current.item_id != reward_id || current.refine >= 1000U) continue;
                ++current.refine;
                reward_slot = candidate;
                break;
            }
        }
        if (!reward_slot.has_value()) {
            for (std::uint16_t candidate = 0U; candidate < 60U; ++candidate) {
                if (!is_inventory_slot_unlocked(updated_inventory, candidate)) continue;
                if (updated_inventory[candidate].item_id == 0U) {
                    reward_slot = candidate;
                    break;
                }
            }
            if (!reward_slot.has_value())
                return send_client_message(socket, "Invent\xE1rio cheio.", client_id);
            database::CharacterItem reward{};
            reward.item_id = reward_id;
            reward.app = reward_id;
            reward.min = reward_definition.durability;
            reward.max = reward_definition.durability;
            reward.refine = 1U;
            if (reward_definition.can_seal != 0U) {
                reward.refine = 0U;
            } else if (reward_definition.expires != 0U) {
                const auto expiry = static_cast<std::uint32_t>(std::time(nullptr)) +
                    (reward_definition.duration + 2U) * 60U * 60U;
                reward.refine = (reward.refine & 0x00ffU) | (expiry & 0x0000ff00U);
                reward.time = (expiry >> 16U) & 0xffffU;
            }
            updated_inventory[*reward_slot] = reward;
        }
        auto& consumed_box = updated_inventory[slot];
        if (consumed_box.refine > 1U) --consumed_box.refine;
        else consumed_box = {};
        const std::vector<database::CharacterItemPlacement> updates{
            {1U, *reward_slot, updated_inventory[*reward_slot]},
            {1U, static_cast<std::uint16_t>(slot), consumed_box}};
        try {
            database::MysqlConnection database{database_config};
            database.save_character_items(character.id, character.gold, updates);
        } catch (const std::exception& error) {
            OutputDebugStringA((std::string{"Aika progression-box persistence failed: "} +
                error.what() + "\n").c_str());
            return true;
        }
        character.inventory = updated_inventory;
        for (const auto& update : updates) {
            auto refresh = make_refresh_item_packet(update.slot_type, update.slot,
                update.item);
            if (!send_encrypted(socket, refresh)) return false;
        }
        return true;
    }

    std::size_t player_class{};
    if (character.class_info >= 1U && character.class_info <= 9U) player_class = 0U;
    else if (character.class_info >= 11U && character.class_info <= 19U) player_class = 1U;
    else if (character.class_info >= 21U && character.class_info <= 29U) player_class = 2U;
    else if (character.class_info >= 31U && character.class_info <= 39U) player_class = 3U;
    else if (character.class_info >= 41U && character.class_info <= 49U) player_class = 4U;
    else if (character.class_info >= 51U && character.class_info <= 59U) player_class = 5U;
    else return true;

    constexpr std::array<std::array<std::uint16_t, 6U>, 6U> event_set_rewards{{
        {{2822U, 2852U, 2882U, 2912U, 6724U, 0U}},
        {{2792U, 2942U, 2972U, 3002U, 3032U, 6689U}},
        {{3062U, 3092U, 3122U, 3152U, 6864U, 0U}},
        {{3182U, 3212U, 3242U, 3272U, 6829U, 0U}},
        {{3302U, 3332U, 3362U, 3392U, 6934U, 0U}},
        {{3422U, 3452U, 3482U, 3512U, 6899U, 0U}}
    }};
    constexpr std::array<std::array<std::uint16_t, 6U>, 6U> blue_academy_rewards{{
        {{12074U, 12380U, 12410U, 12440U, 12470U, 0U}},
        {{12109U, 12350U, 12500U, 12530U, 12560U, 12590U}},
        {{12214U, 12620U, 12650U, 12680U, 12710U, 0U}},
        {{12249U, 12740U, 12770U, 12800U, 12830U, 0U}},
        {{12284U, 12860U, 12890U, 12920U, 12950U, 0U}},
        {{12319U, 12980U, 13010U, 13040U, 13070U, 0U}}
    }};
    constexpr std::array<std::array<std::uint16_t, 6U>, 6U> red_academy_rewards{{
        {{12075U, 12381U, 12411U, 12441U, 12471U, 0U}},
        {{12110U, 12351U, 12501U, 12531U, 12561U, 12591U}},
        {{12215U, 12621U, 12651U, 12681U, 12711U, 0U}},
        {{12250U, 12741U, 12771U, 12801U, 12831U, 0U}},
        {{12285U, 12861U, 12891U, 12921U, 12951U, 0U}},
        {{12320U, 12981U, 13011U, 13041U, 13071U, 0U}}
    }};
    constexpr std::array<std::array<std::uint16_t, 6U>, 6U> novice_set_rewards{{
        {{6727U, 6997U, 7027U, 7057U, 7087U, 0U}},
        {{6692U, 1304U, 7117U, 7147U, 7177U, 7207U}},
        {{6867U, 7237U, 7267U, 7297U, 7327U, 0U}},
        {{6832U, 7357U, 7387U, 7417U, 7447U, 0U}},
        {{6937U, 7477U, 7507U, 7537U, 7567U, 0U}},
        {{6902U, 7597U, 7627U, 7657U, 7687U, 0U}}
    }};
    constexpr std::array<std::array<std::uint16_t, 6U>, 6U> conqueror_rewards{{
        {{1687U, 1717U, 1747U, 1777U, 1063U, 0U}},
        {{1807U, 1837U, 1867U, 1897U, 1028U, 1301U}},
        {{1927U, 1957U, 1987U, 2017U, 1203U, 0U}},
        {{2047U, 2077U, 2107U, 2137U, 1168U, 0U}},
        {{2167U, 2197U, 2227U, 2257U, 1273U, 0U}},
        {{2287U, 2317U, 2347U, 2377U, 1238U, 0U}}
    }};
    constexpr std::array<std::array<std::uint16_t, 6U>, 6U> rare_event_rewards{{
        {{2579U, 2834U, 2864U, 2894U, 2924U, 0U}},
        {{2544U, 2954U, 2984U, 3014U, 3044U, 2804U}},
        {{2719U, 3074U, 3104U, 3134U, 3164U, 0U}},
        {{2684U, 3194U, 3224U, 3254U, 3284U, 0U}},
        {{2789U, 3314U, 3344U, 3374U, 3404U, 0U}},
        {{2754U, 3434U, 3464U, 3494U, 3524U, 0U}}
    }};
    std::array<std::uint16_t, 6U> fixed_rewards{};
    const std::array<std::uint16_t, 6U>* rewards = nullptr;
    std::uint32_t reward_refine = 1U;
    std::array<std::uint32_t, 6U> reward_refines{};
    bool use_reward_refines{};
    std::size_t required_free_slots = 5U;
    if (effect == 1089U) {
        thread_local std::mt19937 generator{std::random_device{}()};
        std::uniform_int_distribution<std::uint16_t> color_roll{1U, 3U};
        rewards = color_roll(generator) == 1U
            ? &red_academy_rewards[player_class]
            : &blue_academy_rewards[player_class];
        reward_refine = 0U;
        if (player_class == 1U) required_free_slots = 6U;
    } else if (effect == 137U) {
        fixed_rewards = {{2846U, 2876U, 2906U, 2936U, 2561U, 0U}};
        rewards = &fixed_rewards;
        reward_refine = 80U;
    } else if (effect == 138U) {
        fixed_rewards = {{2966U, 2996U, 3026U, 3056U, 2526U, 2816U}};
        rewards = &fixed_rewards;
        reward_refines = {{5U, 5U, 5U, 5U, 80U, 80U}};
        use_reward_refines = true;
        required_free_slots = 6U;
    } else if (effect == 139U) {
        fixed_rewards = {{3086U, 3116U, 3146U, 3176U, 2701U, 0U}};
        rewards = &fixed_rewards;
        reward_refine = 80U;
    } else if (effect == 140U) {
        fixed_rewards = {{3206U, 3236U, 3266U, 3296U, 2666U, 0U}};
        rewards = &fixed_rewards;
        reward_refine = 80U;
    } else if (effect == 141U) {
        fixed_rewards = {{3326U, 3356U, 3386U, 3416U, 2771U, 0U}};
        rewards = &fixed_rewards;
        reward_refine = 80U;
    } else if (effect == 142U) {
        fixed_rewards = {{3446U, 3476U, 3506U, 3536U, 2736U, 0U}};
        rewards = &fixed_rewards;
        reward_refine = 80U;
    } else if (effect == 39U) {
        fixed_rewards = {{7008U, 7038U, 7068U, 7098U, 0U, 0U}};
        rewards = &fixed_rewards;
        reward_refine = 0U;
        required_free_slots = 4U;
    } else if (effect == 41U) {
        fixed_rewards = {{7127U, 7157U, 7187U, 7217U, 0U, 0U}};
        rewards = &fixed_rewards;
        reward_refine = 0U;
        required_free_slots = 4U;
    } else if (effect == 42U) {
        fixed_rewards = {{7248U, 7278U, 7308U, 7338U, 0U, 0U}};
        rewards = &fixed_rewards;
        reward_refine = 0U;
        required_free_slots = 4U;
    } else if (effect == 43U) {
        fixed_rewards = {{7368U, 7398U, 7428U, 7458U, 0U, 0U}};
        rewards = &fixed_rewards;
        reward_refine = 0U;
        required_free_slots = 4U;
    } else if (effect == 44U) {
        fixed_rewards = {{7488U, 7518U, 7548U, 7578U, 0U, 0U}};
        rewards = &fixed_rewards;
        reward_refine = 0U;
        required_free_slots = 4U;
    } else if (effect == 45U) {
        fixed_rewards = {{7608U, 7638U, 7668U, 7698U, 0U, 0U}};
        rewards = &fixed_rewards;
        reward_refine = 0U;
        required_free_slots = 4U;
    } else if (effect == 1U) {
        rewards = &novice_set_rewards[player_class];
        reward_refine = player_class >= 2U ? 112U : 1U;
    } else if (effect == 5289U || effect == 1133U) {
        rewards = &event_set_rewards[player_class];
        reward_refine = 48U;
    } else if (effect >= 1138U && effect <= 1141U) {
        rewards = &rare_event_rewards[player_class];
        reward_refine = effect <= 1139U ? 64U : 128U;
    } else if (effect == 1142U || effect == 1857U) {
        fixed_rewards = {{13216U, 13217U, 13218U, 13219U, 0U, 0U}};
        rewards = &fixed_rewards;
        if (effect == 1857U) required_free_slots = 4U;
    } else if (effect == 1856U) {
        fixed_rewards = {{1615U, 1616U, 1617U, 1618U, 0U, 0U}};
        rewards = &fixed_rewards;
        required_free_slots = 4U;
    } else if (effect == 18855U) {
        fixed_rewards = {{13190U, 13191U, 13192U, 13193U, 0U, 0U}};
        rewards = &fixed_rewards;
        required_free_slots = 4U;
    } else if (effect == 1854U) {
        fixed_rewards = {{13224U, 13225U, 13226U, 13227U, 0U, 0U}};
        rewards = &fixed_rewards;
        required_free_slots = 4U;
    } else if (effect == 1105U) {
        fixed_rewards = {{18738U, 18739U, 18740U, 18741U, 0U, 0U}};
        rewards = &fixed_rewards;
        required_free_slots = 4U;
    } else if (effect == 1143U) {
        rewards = &blue_academy_rewards[player_class];
    } else if (effect == 1144U) {
        rewards = &red_academy_rewards[player_class];
    } else if (effect == 1145U) {
        rewards = &conqueror_rewards[player_class];
    }
    if (rewards == nullptr) return true;
    const auto reward_count = static_cast<std::size_t>(std::count_if(
        rewards->begin(), rewards->end(), [](const std::uint16_t id) { return id != 0U; }));
    std::vector<std::uint16_t> empty_slots;
    empty_slots.reserve(reward_count);
    for (std::uint16_t candidate = 0U; candidate < 60U &&
            empty_slots.size() < (std::max)(reward_count, required_free_slots); ++candidate)
        if (is_inventory_slot_unlocked(character.inventory, candidate) &&
            character.inventory[candidate].item_id == 0U)
            empty_slots.push_back(candidate);
    if (empty_slots.size() < (std::max)(reward_count, required_free_slots))
        return send_client_message(socket, "Inventario cheio.", client_id);

    auto updated_inventory = character.inventory;
    auto& consumed_box = updated_inventory[slot];
    if (consumed_box.refine > 1U) --consumed_box.refine;
    else consumed_box = {};

    std::vector<database::CharacterItemPlacement> updates;
    updates.reserve(reward_count + 1U);
    updates.push_back({1U, static_cast<std::uint16_t>(slot), consumed_box});
    std::size_t reward_slot{};
    for (const auto item_id : *rewards) {
        if (item_id == 0U) continue;
        if (item_id >= tables.item_definitions.size()) return true;
        const auto& definition = tables.item_definitions[item_id];
        database::CharacterItem item{};
        item.item_id = item_id;
        item.app = item_id;
        item.min = definition.durability;
        item.max = definition.durability;
        item.refine = use_reward_refines ? reward_refines[reward_slot] : reward_refine;
        if (definition.can_seal != 0U) {
            item.refine = 0U;
        } else if (definition.expires != 0U) {
            const auto expiry = static_cast<std::uint32_t>(std::time(nullptr)) +
                (definition.duration + 2U) * 60U * 60U;
            item.refine = (item.refine & 0x00ffU) | (expiry & 0x0000ff00U);
            item.time = (expiry >> 16U) & 0xffffU;
        }
        updated_inventory[empty_slots[reward_slot]] = item;
        updates.push_back({1U, empty_slots[reward_slot], item});
        ++reward_slot;
    }

    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(character.id, character.gold, updates);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika equipment-box persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    character.inventory = updated_inventory;
    for (std::size_t index = 1U; index < updates.size(); ++index) {
        const auto& update = updates[index];
        auto refresh = make_refresh_item_packet(update.slot_type, update.slot, update.item);
        if (!send_encrypted(socket, refresh)) return false;
    }
    std::string_view reward_message;
    switch (effect) {
    case 1857U: reward_message = "Voc\xEA recebeu o Kit Completo do 1\xBA Anivers\xE1rio!"; break;
    case 1856U: reward_message = "Voc\xEA recebeu o Kit Completo do 2\xBA Anivers\xE1rio!"; break;
    case 18855U: reward_message = "Voc\xEA recebeu o Kit Completo do 3\xBA Anivers\xE1rio!"; break;
    case 1854U: reward_message = "Voc\xEA recebeu o Kit Completo do 4\xBA Anivers\xE1rio!"; break;
    case 1105U: reward_message = "Voc\xEA recebeu o Kit Comemorativo completo!"; break;
    default: break;
    }
    if (!reward_message.empty() &&
        !send_client_message(socket, reward_message, client_id)) return false;
    const auto& consumed_update = updates.front();
    auto consumed_refresh = make_refresh_item_packet(consumed_update.slot_type,
        consumed_update.slot, consumed_update.item);
    if (!send_encrypted(socket, consumed_refresh)) return false;
    return true;
}

[[nodiscard]] bool handle_use_reward_box(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session) {
    if (request.size() < 24U || !session.entered_world ||
        !session.selected_character.has_value() || read_u32(request, 12U) != 1U)
        return true;
    auto& character = *session.selected_character;
    const auto requested_slot = read_u32(request, 16U);
    if (requested_slot >= 60U) return true;
    const auto& box = character.inventory[requested_slot];
    if (box.item_id == 0U || box.item_id >= tables.item_definitions.size()) return true;
    const auto& box_definition = tables.item_definitions[box.item_id];
    const auto effect = box_definition.use_effect;
    const bool supported_box_type = box_definition.item_type == 714U ||
        (box_definition.item_type == 705U && (effect == 1U || effect == 98U ||
            effect == 629U || effect == 910U || effect == 950U || effect == 1030U ||
            effect == 1130U || effect == 16020U ||
            (effect >= 16000U && effect <= 16004U)));
    if (!supported_box_type ||
        (session.account.account_type != 5U && box_definition.level > character.level))
        return true;

    struct Reward final { std::uint16_t item_id; std::uint16_t quantity; };
    std::vector<Reward> rewards;
    std::size_t required_free_slots{};
    const auto select_random_item = [](const auto& items, const auto& chances) {
        thread_local std::mt19937 generator{std::random_device{}()};
        std::uniform_int_distribution<std::uint16_t> roll_distribution{0U, 99U};
        const auto roll = roll_distribution(generator);
        std::vector<std::size_t> candidates;
        for (std::size_t index = 0U; index < items.size(); ++index)
            if (roll <= chances[index]) candidates.push_back(index);
        if (candidates.empty()) {
            std::uniform_int_distribution<std::size_t> item_distribution{
                0U, items.size() - 1U};
            return items[item_distribution(generator)];
        }
        std::uniform_int_distribution<std::size_t> candidate_distribution{
            0U, candidates.size() - 1U};
        return items[candidates[candidate_distribution(generator)]];
    };
    const auto random_between = [](std::uint16_t minimum, std::uint16_t maximum) {
        thread_local std::mt19937 generator{std::random_device{}()};
        std::uniform_int_distribution<std::uint16_t> distribution{minimum, maximum};
        return distribution(generator);
    };
    switch (effect) {
    case 1U:
        rewards = {{11678U, 1U}, {11680U, 1U}};
        required_free_slots = 1U;
        break;
    case 629U:
        rewards = {{1335U, 1U}, {1363U, 1U}, {1393U, 1U}, {1418U, 1U}};
        required_free_slots = 4U;
        break;
    case 98U: {
        constexpr std::array<std::uint16_t, 16U> items{{
            4220U, 4221U, 4222U, 4223U, 4224U, 4225U, 4226U, 4227U,
            4228U, 4229U, 4230U, 4231U, 4234U, 4235U, 4240U, 4241U}};
        constexpr std::array<std::uint16_t, 16U> chances{{
            20U, 20U, 20U, 20U, 20U, 20U, 15U, 15U,
            15U, 5U, 25U, 25U, 3U, 5U, 5U, 5U}};
        rewards = {{select_random_item(items, chances), 1U}};
        required_free_slots = 1U;
        break;
    }
    case 910U: {
        constexpr std::array<std::uint16_t, 15U> items{{
            9451U, 9452U, 9453U, 9454U, 9455U, 9456U, 9457U, 9458U,
            9459U, 9460U, 9461U, 9462U, 9463U, 9464U, 9465U}};
        constexpr std::array<std::uint16_t, 15U> chances{{
            5U, 5U, 2U, 2U, 2U, 25U, 25U, 25U,
            25U, 25U, 15U, 15U, 5U, 5U, 30U}};
        rewards = {{select_random_item(items, chances), 1U}};
        required_free_slots = 1U;
        break;
    }
    case 1030U: {
        const auto roll = random_between(1U, 100U);
        std::uint16_t item_id = 5768U;
        if (roll == 1U) {
            const auto branch = random_between(1U, 100U);
            if (branch <= 20U)
                item_id = random_between(1U, 3U) <= 2U ? 8210U : 8207U;
            else if (branch <= 40U)
                item_id = random_between(1U, 3U) <= 2U ? 8188U : 8186U;
        } else if (roll >= 2U && roll <= 45U) {
            const auto branch = random_between(1U, 100U);
            if (branch <= 5U) item_id = 8063U;
            else if (branch <= 10U) item_id = 8064U;
            else if (branch <= 20U) item_id = 4857U;
            else if (branch <= 30U) item_id = 4858U;
            else if (branch <= 40U) item_id = 4859U;
        } else if (roll == 86U || roll == 87U) {
            item_id = 15978U;
        } else if (roll == 88U || roll == 94U) {
            item_id = 17031U;
        } else if (roll == 89U) {
            item_id = 9572U;
        } else if (roll == 91U) {
            item_id = 8270U;
        } else if (roll >= 95U) {
            const auto branch = random_between(1U, 100U);
            if (branch <= 24U) item_id = 1335U;
            else if (branch <= 49U) item_id = 1363U;
            else if (branch <= 74U) item_id = 1393U;
            else item_id = 1418U;
        }
        rewards = {{item_id, 1U}};
        required_free_slots = 1U;
        break;
    }
    case 16020U: {
        constexpr std::array<std::uint16_t, 2U> branches{{1U, 2U}};
        constexpr std::array<std::uint16_t, 2U> branch_chances{{8U, 98U}};
        const auto branch = select_random_item(branches, branch_chances);
        if (branch == 1U) {
            const auto tier = random_between(1U, 40U);
            std::uint16_t reward{};
            if (tier <= 20U)
                reward = random_between(1U, 3U) <= 2U ? 8210U : 8207U;
            else
                reward = random_between(1U, 3U) <= 2U ? 8188U : 8186U;
            rewards = {{reward, 1U}};
        } else {
            const auto roll = random_between(1U, 104U);
            if (roll <= 10U) rewards = {{8105U, 1U}};
            else if (roll <= 20U) rewards = {{8106U, 1U}};
            else if (roll <= 30U) rewards = {{8107U, 1U}};
            else if (roll <= 40U) rewards = {{8108U, 1U}};
            else if (roll <= 50U) rewards = {{8109U, 1U}};
            else if (roll <= 60U) rewards = {{8110U, 1U}};
            else if (roll <= 70U) rewards = {{8111U, 2U}};
            else if (roll <= 80U) rewards = {{8114U, 1U}, {8124U, 4U}};
            else if (roll <= 90U) rewards = {{8115U, 1U}, {8125U, 4U}};
            else if (roll <= 92U) rewards = {{8132U, 1U}};
            else if (roll <= 94U) rewards = {{8133U, 1U}};
            else if (roll <= 96U) rewards = {{8134U, 1U}};
            else if (roll <= 98U) rewards = {{8137U, 1U}};
            else if (roll == 99U || roll == 104U) rewards = {{4519U, 1U}};
        }
        required_free_slots = 2U;
        break;
    }
    case 950U:
    case 1130U: {
        constexpr std::array<std::uint16_t, 36U> items{{
            5329U, 5332U, 5335U, 5338U, 5341U, 5344U, 5348U, 5492U, 5495U,
            5350U, 5353U, 5356U, 5359U, 5362U, 5365U, 5368U, 5371U, 5374U,
            5497U, 5396U, 5398U, 5402U, 5405U, 5408U, 5411U, 5413U, 5416U,
            5419U, 5422U, 5425U, 5446U, 5449U, 5499U, 5500U, 5490U, 5498U}};
        constexpr std::array<std::uint16_t, 36U> chances{{
            25U, 25U, 25U, 15U, 15U, 10U, 15U, 15U, 15U, 15U, 10U, 20U,
            15U, 15U, 15U, 15U, 12U, 13U, 20U, 20U, 25U, 25U, 10U, 10U,
            20U, 15U, 25U, 25U, 25U, 25U, 25U, 12U, 15U, 15U, 12U, 5U}};
        rewards = {{select_random_item(items, chances), 1U}};
        required_free_slots = 1U;
        break;
    }
    case 16003U:
    case 16004U: {
        constexpr std::array<std::uint16_t, 7U> mount_items{{
            9572U, 4274U, 8262U, 4359U, 4379U, 8063U, 8064U}};
        constexpr std::array<std::uint16_t, 7U> pran_items{{
            8270U, 11454U, 8262U, 4359U, 4379U, 8063U, 8064U}};
        constexpr std::array<std::uint16_t, 7U> chances{{
            2U, 4U, 8U, 16U, 16U, 48U, 48U}};
        const auto item_id = effect == 16003U
            ? select_random_item(mount_items, chances)
            : select_random_item(pran_items, chances);
        rewards = {{item_id, 1U}};
        required_free_slots = 1U;
        break;
    }
    case 16000U: {
        constexpr std::array<std::uint16_t, 8U> items{{
            9572U, 8151U, 8159U, 8262U, 4359U, 4379U, 8063U, 8064U}};
        constexpr std::array<std::uint16_t, 8U> chances{{
            2U, 2U, 4U, 8U, 16U, 16U, 48U, 48U}};
        auto item_id = select_random_item(items, chances);
        if (item_id == 9572U) {
            constexpr std::array<std::uint16_t, 7U> weapons{{
                5349U, 5335U, 5338U, 5341U, 5329U, 5332U, 5344U}};
            constexpr std::array<std::uint16_t, 7U> weapon_chances{{
                5U, 5U, 5U, 5U, 15U, 15U, 20U}};
            item_id = select_random_item(weapons, weapon_chances);
        }
        rewards = {{item_id, 1U}};
        required_free_slots = 1U;
        break;
    }
    case 16001U: {
        constexpr std::array<std::uint16_t, 8U> items{{
            9572U, 8169U, 8177U, 8262U, 4359U, 4379U, 8063U, 8064U}};
        constexpr std::array<std::uint16_t, 8U> chances{{
            4U, 2U, 4U, 8U, 16U, 16U, 48U, 48U}};
        auto item_id = select_random_item(items, chances);
        if (item_id == 9572U) {
            constexpr std::array<std::uint16_t, 9U> armor{{
                5369U, 5365U, 5362U, 5359U, 5353U, 5350U, 5356U, 5371U, 5374U}};
            constexpr std::array<std::uint16_t, 9U> armor_chances{{
                4U, 2U, 4U, 4U, 15U, 15U, 20U, 25U, 25U}};
            item_id = select_random_item(armor, armor_chances);
        }
        rewards = {{item_id, 1U}};
        required_free_slots = 1U;
        break;
    }
    case 16002U: {
        constexpr std::array<std::uint16_t, 10U> items{{
            9572U, 6502U, 6503U, 6504U, 6505U, 8262U, 4359U, 4379U, 8063U, 8064U}};
        constexpr std::array<std::uint16_t, 10U> chances{{
            2U, 1U, 1U, 1U, 1U, 8U, 16U, 16U, 48U, 48U}};
        auto item_id = select_random_item(items, chances);
        if (item_id == 9572U) {
            constexpr std::array<std::uint16_t, 9U> accessories{{
                5404U, 5402U, 5395U, 5411U, 5413U, 5416U, 5419U, 5422U, 5425U}};
            constexpr std::array<std::uint16_t, 9U> accessory_chances{{
                4U, 2U, 1U, 2U, 2U, 15U, 15U, 15U, 15U}};
            item_id = select_random_item(accessories, accessory_chances);
        }
        rewards = {{item_id, 1U}};
        required_free_slots = 1U;
        break;
    }
    case 357U:
        rewards = {{4520U, 5U}, {4521U, 5U}, {8200U, 5U}, {4358U, 10U}, {4398U, 10U}};
        required_free_slots = 5U;
        break;
    case 666U:
        rewards = {{8025U, 1U}, {1611U, 1U}, {10045U, 1U}};
        required_free_slots = 3U;
        break;
    case 667U:
        rewards = {{8027U, 1U}, {1612U, 1U}, {4514U, 50U},
            {8189U, 50U}, {4438U, 1U}, {10046U, 1U}};
        required_free_slots = 5U;
        break;
    case 668U:
        rewards = {{13528U, 1U}, {1614U, 1U}, {4514U, 50U},
            {8189U, 50U}, {10047U, 1U}};
        required_free_slots = 5U;
        break;
    case 669U:
        rewards = {{7930U, 1U}, {1613U, 1U}, {4514U, 50U},
            {8212U, 20U}, {10048U, 1U}};
        required_free_slots = 5U;
        break;
    case 670U:
        rewards = {{7927U, 1U}, {4514U, 50U}, {8212U, 20U}, {10049U, 1U}};
        required_free_slots = 4U;
        break;
    case 671U:
        rewards = {{8199U, 100U}, {8253U, 100U}, {8185U, 4U}, {8187U, 4U},
            {8206U, 2U}, {8209U, 2U}, {4483U, 1U}, {4487U, 1U}, {10050U, 1U}};
        required_free_slots = 9U;
        break;
    case 672U:
        rewards = {{4480U, 1U}, {4481U, 1U}, {8252U, 100U}, {8254U, 100U},
            {8204U, 4U}, {8205U, 4U}, {8208U, 2U}, {8211U, 2U},
            {4373U, 1000U}, {4405U, 1000U}, {10051U, 1U}};
        required_free_slots = 11U;
        break;
    case 673U:
        rewards = {{4480U, 1U}, {4481U, 1U}, {8259U, 100U}, {8260U, 100U},
            {8222U, 4U}, {8171U, 4U}, {8229U, 2U}, {8243U, 2U},
            {4376U, 1000U}, {4407U, 1000U}, {8858U, 1U}, {10295U, 1U},
            {10052U, 1U}};
        required_free_slots = 11U;
        break;
    case 674U:
        rewards = {{4480U, 1U}, {4481U, 1U}, {8261U, 100U}, {8262U, 100U},
            {8204U, 4U}, {8205U, 4U}, {8230U, 2U}, {8231U, 2U},
            {4376U, 1500U}, {4407U, 1500U}, {10053U, 1U}};
        required_free_slots = 10U;
        break;
    case 675U:
        rewards = {{4480U, 1U}, {4481U, 1U}, {8263U, 100U}, {8264U, 100U},
            {8224U, 4U}, {8225U, 4U}, {8244U, 2U}, {8245U, 2U},
            {4376U, 2000U}, {4407U, 2000U}};
        required_free_slots = 10U;
        break;
    case 1787U:
        rewards = {{12107U, 1U}, {12348U, 1U}};
        required_free_slots = 2U;
        break;
    case 1858U:
        rewards = {{964U, 1U}, {9572U, 2U}};
        required_free_slots = 3U;
        break;
    case 1859U:
        rewards = {{965U, 1U}, {9572U, 2U}};
        required_free_slots = 3U;
        break;
    case 1860U:
        rewards = {{963U, 1U}, {9572U, 2U}};
        required_free_slots = 3U;
        break;
    default:
        return true;
    }

    const auto empty_count = empty_unlocked_inventory_slots(character.inventory);
    if (empty_count < required_free_slots)
        return send_client_message(socket, "Invent\xE1rio cheio.", client_id);

    auto updated_inventory = character.inventory;
    std::vector<database::CharacterItemPlacement> updates;
    for (const auto& reward : rewards) {
        if (reward.item_id == 0U || reward.item_id >= tables.item_definitions.size())
            return true;
        const auto& definition = tables.item_definitions[reward.item_id];
        auto remaining = static_cast<std::uint32_t>(reward.quantity);
        bool placed{};
        if (definition.can_group != 0U) {
            for (std::uint16_t candidate = 0U;
                 candidate < 60U && remaining > 0U; ++candidate) {
                auto& current = updated_inventory[candidate];
                if (!is_inventory_slot_unlocked(updated_inventory, candidate) ||
                    current.item_id != reward.item_id || current.refine >= 1000U) continue;
                const auto amount = (std::min)(remaining, 1000U - current.refine);
                current.refine += amount;
                remaining -= amount;
                updates.push_back({1U, candidate, current});
                placed = true;
            }
        }
        if (!definition.can_group || reward.quantity == 0U) remaining = 0U;
        while (remaining > 0U || !placed) {
            std::optional<std::uint16_t> empty_slot;
            for (std::uint16_t candidate = 0U; candidate < 60U; ++candidate) {
                if (!is_inventory_slot_unlocked(updated_inventory, candidate)) continue;
                if (updated_inventory[candidate].item_id == 0U) {
                    empty_slot = candidate;
                    break;
                }
            }
            if (!empty_slot.has_value())
                return send_client_message(socket, "Invent\xE1rio cheio.", client_id);
            const auto quantity_to_place = remaining;
            database::CharacterItem item{};
            item.item_id = reward.item_id;
            item.app = reward.item_id;
            item.min = definition.durability;
            item.max = definition.durability;
            item.refine = definition.can_group != 0U
                ? (reward.quantity == 0U ? 0U : remaining) : reward.quantity;
            if (definition.can_seal != 0U) {
                item.refine = 0U;
            } else if (definition.expires != 0U) {
                const auto expiry = static_cast<std::uint32_t>(std::time(nullptr)) +
                    (definition.duration + 2U) * 60U * 60U;
                item.refine = (item.refine & 0x00ffU) | (expiry & 0x0000ff00U);
                item.time = (expiry >> 16U) & 0xffffU;
            }
            updated_inventory[*empty_slot] = item;
            updates.push_back({1U, *empty_slot, item});
            placed = true;
            if (definition.can_group == 0U || reward.quantity == 0U) break;
            remaining -= quantity_to_place;
        }
    }

    auto& consumed_box = updated_inventory[requested_slot];
    if (consumed_box.refine > 1U) --consumed_box.refine;
    else consumed_box = {};
    updates.push_back({1U, static_cast<std::uint16_t>(requested_slot), consumed_box});
    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(character.id, character.gold, updates);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika reward-box persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    character.inventory = updated_inventory;
    for (std::size_t index = 0U; index + 1U < updates.size(); ++index) {
        const auto& update = updates[index];
        auto refresh = make_refresh_item_packet(update.slot_type, update.slot, update.item);
        if (!send_encrypted(socket, refresh)) return false;
    }
    if (effect == 1787U && !send_client_message(socket,
            "Voc\xEA recebeu L\xE2mina e Escudo do Poder Justo!", client_id))
        return false;
    const auto& consumed_update = updates.back();
    auto consumed_refresh = make_refresh_item_packet(consumed_update.slot_type,
        consumed_update.slot, consumed_update.item);
    if (!send_encrypted(socket, consumed_refresh)) return false;
    return true;
}

[[nodiscard]] bool handle_use_title_box(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session) {
    if (request.size() < 24U || !session.entered_world ||
        !session.selected_character.has_value() || read_u32(request, 12U) != 1U)
        return true;
    auto& character = *session.selected_character;
    const auto slot = read_u32(request, 16U);
    if (slot >= 60U) return true;
    const auto& box = character.inventory[slot];
    if (box.item_id == 0U || box.item_id >= tables.item_definitions.size()) return true;
    const auto& definition = tables.item_definitions[box.item_id];
    if (definition.item_type != 705U ||
        (definition.use_effect != 10766U && definition.use_effect != 10767U &&
         definition.use_effect != 10768U) ||
        (session.account.account_type != 5U && definition.level > character.level))
        return true;

    const std::uint16_t title_id = definition.use_effect == 10766U ? 78U
        : definition.use_effect == 10767U ? 94U : 95U;
    if (title_id >= tables.titles.size()) return true;
    const auto available = std::find_if(character.titles.begin(), character.titles.end(),
        [](const database::CharacterTitle& title) { return title.index == 0U; });
    if (available == character.titles.end())
        return send_client_message(socket, "Sua lista de t\xEDtulos est\xE1 cheia.", client_id);
    const auto& title_definition = tables.titles[title_id].levels[0U];
    const database::CharacterTitle title{title_id, 1U, title_definition.goal};
    auto updated_inventory = character.inventory;
    auto& consumed_box = updated_inventory[slot];
    if (consumed_box.refine > 1U) --consumed_box.refine;
    else consumed_box = {};
    const std::vector<database::CharacterItemPlacement> updates{
        {1U, static_cast<std::uint16_t>(slot), consumed_box}};
    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(character.id, character.gold, updates,
            {}, std::nullopt, std::nullopt, std::nullopt, std::nullopt,
            {}, {}, std::nullopt, {title});
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika title-box persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    character.inventory = updated_inventory;
    *available = title;

    protocol::PacketHeader header{};
    header.size = 20U;
    header.client_index = client_id;
    header.opcode = 0x017dU;
    auto title_packet = std::vector<std::byte>(header.size);
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), title_packet.begin());
    write_u32(title_id, title_packet, 12U);
    write_u32(0U, title_packet, 16U);
    if (!send_encrypted(socket, title_packet)) return false;
    const std::string title_name{title_definition.name.begin(),
        std::find(title_definition.name.begin(), title_definition.name.end(), '\0')};
    const auto message = std::string{"Voc\xEA obteve um novo t\xEDtulo ["} +
        title_name + "]";
    if (!send_client_message(socket, message, client_id)) return false;
    auto refresh = make_refresh_item_packet(1U, static_cast<std::uint16_t>(slot),
        consumed_box);
    return send_encrypted(socket, refresh);
}

[[nodiscard]] bool handle_use_random_gold_box(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session) {
    if (request.size() < 24U || !session.entered_world ||
        !session.selected_character.has_value() || read_u32(request, 12U) != 1U)
        return true;
    auto& character = *session.selected_character;
    const auto slot = read_u32(request, 16U);
    if (slot >= 60U) return true;
    const auto& box = character.inventory[slot];
    if (box.item_id == 0U || box.item_id >= tables.item_definitions.size()) return true;
    const auto& definition = tables.item_definitions[box.item_id];
    if (definition.item_type != 705U || definition.use_effect != 198U ||
        (session.account.account_type != 5U && definition.level > character.level))
        return true;

    const auto empty_count = empty_unlocked_inventory_slots(character.inventory);
    if (empty_count == 0)
        return send_client_message(socket, "Invent\xE1rio cheio.", client_id);

    constexpr std::array<std::uint64_t, 5U> gold_rewards{
        1'000U, 10'000U, 50'000U, 100'000U, 1'000'000U};
    thread_local std::mt19937 generator{std::random_device{}()};
    std::uniform_int_distribution<std::size_t> select_reward{0U,
        gold_rewards.size() - 1U};
    const auto amount = gold_rewards[select_reward(generator)];
    const auto updated_gold = character.gold + amount;
    auto updated_box = box;
    if (updated_box.refine > 1U) --updated_box.refine;
    else updated_box = {};
    const std::vector<database::CharacterItemPlacement> updates{
        {1U, static_cast<std::uint16_t>(slot), updated_box}};
    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(character.id, updated_gold, updates);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika random-gold box persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    character.gold = updated_gold;
    character.inventory[slot] = updated_box;
    auto money = make_refresh_money_packet(character, session.account);
    std::vector<std::byte> money_packet(money.begin(), money.end());
    if (!send_encrypted(socket, money_packet)) return false;
    std::ostringstream formatted_amount;
    formatted_amount.imbue(std::locale{""});
    formatted_amount << amount;
    if (!send_client_message(socket,
            "Parab\xE9ns! Voc\xEA ganhou " + formatted_amount.str() + " de Gold!",
            client_id))
        return false;
    auto refresh = make_refresh_item_packet(1U, static_cast<std::uint16_t>(slot),
        updated_box);
    return send_encrypted(socket, refresh);
}

[[nodiscard]] bool handle_use_inventory_bag(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session) {
    if (request.size() < 24U || !session.entered_world ||
        !session.selected_character.has_value() || read_u32(request, 12U) != 1U)
        return true;
    const auto slot = read_u32(request, 16U);
    if (slot >= 60U) return true;
    auto& character = *session.selected_character;
    const auto item = character.inventory[slot];
    if (!is_inventory_slot_unlocked(character.inventory,
            static_cast<std::uint16_t>(slot))) return true;
    if (item.item_id == 0U || item.item_id >= tables.item_definitions.size()) return true;
    const auto& definition = tables.item_definitions[item.item_id];
    if (definition.item_type != 217U ||
        (session.account.account_type != 5U && definition.level > character.level))
        return true;
    // TItemFunctions.UseItem in Delphi fixes ITEM_TYPE_BAG_INV at slot 63.
    constexpr std::uint16_t bag_slot = 63U;
    if (character.inventory[bag_slot].item_id != 0U)
        return send_client_message(socket,
            "Todas as expansoes da mochila ja estao ocupadas.", client_id);

    auto activated_bag = item;
    if (definition.expires != 0U) {
        const auto expiry = static_cast<std::uint32_t>(std::time(nullptr)) +
            (static_cast<std::uint32_t>(definition.duration) + 2U) * 60U * 60U;
        // Delphi stores the Unix expiry in the upper byte of refine and both
        // bytes of time, preserving only the low byte of the previous refine.
        activated_bag.refine = (activated_bag.refine & 0x00ffU) |
            (expiry & 0x0000ff00U);
        activated_bag.time = (expiry >> 16U) & 0xffffU;
    }
    auto updated_character = character;
    updated_character.inventory[bag_slot] = activated_bag;
    updated_character.inventory[slot] = {};
    const std::vector<database::CharacterItemPlacement> updates{
        {1U, static_cast<std::uint16_t>(slot), {}},
        {1U, bag_slot, activated_bag}};
    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(character.id, character.gold, updates);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika inventory-bag persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    character.inventory = updated_character.inventory;
    std::clog << "[game] inventory bag activated client=" << client_id
              << " source_slot=" << slot << " bag_slot=" << bag_slot
              << " item_id=" << item.item_id << std::endl;
    auto bag_refresh = make_refresh_item_packet(1U, bag_slot, activated_bag);
    if (!send_encrypted(socket, bag_refresh)) return false;
    const auto name_end = std::find(definition.name.begin(), definition.name.end(), '\0');
    const std::string item_name{definition.name.begin(), name_end};
    if (!send_client_message(socket,
            "Selo de [" + item_name + "] foi removido.", client_id)) return false;
    auto consumed_refresh = make_refresh_item_packet(1U,
        static_cast<std::uint16_t>(slot), {});
    return send_encrypted(socket, consumed_refresh);
}

[[nodiscard]] bool handle_use_storage_bag(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session) {
    if (request.size() < 24U || !session.entered_world ||
        !session.selected_character.has_value() || read_u32(request, 12U) != 1U)
        return true;
    const auto source_slot = read_u32(request, 16U);
    if (source_slot >= 60U) return true;
    auto& character = *session.selected_character;
    const auto bag = character.inventory[source_slot];
    if (!is_inventory_slot_unlocked(character.inventory,
            static_cast<std::uint16_t>(source_slot))) return true;
    if (bag.item_id == 0U || bag.item_id >= tables.item_definitions.size()) return true;
    const auto& definition = tables.item_definitions[bag.item_id];
    if (definition.item_type != 218U ||
        (session.account.account_type != 5U && definition.level > character.level))
        return true;

    std::optional<std::uint16_t> destination_slot;
    for (std::uint16_t candidate = 81U; candidate <= 83U; ++candidate)
        if (session.account.storage_items[candidate].item_id == 0U)
            destination_slot = candidate;
    if (!destination_slot.has_value())
        return send_client_message(socket, "Limite de expans\xE3o atingido.", client_id);

    auto activated_bag = bag;
    if (definition.expires != 0U) {
        const auto expiry = static_cast<std::uint32_t>(std::time(nullptr)) +
            (static_cast<std::uint32_t>(definition.duration) + 2U) * 60U * 60U;
        activated_bag.refine = (activated_bag.refine & 0x00ffU) |
            (expiry & 0x0000ff00U);
        activated_bag.time = (expiry >> 16U) & 0xffffU;
    }
    const database::CharacterItem consumed_bag{};
    const std::vector<database::CharacterItemPlacement> updates{
        {1U, static_cast<std::uint16_t>(source_slot), consumed_bag},
        {2U, *destination_slot, activated_bag}};
    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(character.id, character.gold, updates,
            {}, std::nullopt, std::nullopt, std::nullopt, std::nullopt,
            {}, {}, std::nullopt, {}, session.account.id);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika storage-bag persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    character.inventory[source_slot] = consumed_bag;
    session.account.storage_items[*destination_slot] = activated_bag;
    auto storage_refresh = make_refresh_item_packet(2U, *destination_slot, activated_bag);
    if (!send_encrypted(socket, storage_refresh)) return false;
    const auto name_end = std::find(definition.name.begin(), definition.name.end(), '\0');
    const std::string item_name{definition.name.begin(), name_end};
    if (!send_client_message(socket,
            "Selo de [" + item_name + "] foi removido.", client_id)) return false;
    auto inventory_refresh = make_refresh_item_packet(1U,
        static_cast<std::uint16_t>(source_slot), consumed_bag);
    return send_encrypted(socket, inventory_refresh);
}

[[nodiscard]] bool handle_open_storage_item(const SOCKET socket,
        const std::span<const std::byte> request,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session) {
    if (request.size() < 24U || !session.entered_world ||
        !session.selected_character.has_value() || read_u32(request, 12U) != 1U)
        return true;
    const auto slot = read_u32(request, 16U);
    if (slot >= 60U) return true;
    const auto& character = *session.selected_character;
    const auto item_id = character.inventory[slot].item_id;
    if (item_id == 0U || item_id >= tables.item_definitions.size()) return true;
    const auto& definition = tables.item_definitions[item_id];
    if (definition.item_type != 226U ||
        (session.account.account_type != 5U && definition.level > character.level))
        return true;

    auto storage = make_storage_packet(session.account, client_id);
    if (!send_encrypted(socket, storage)) return false;
    const auto opened_packet = make_signal_packet(client_id, 0x0310U, 1U);
    std::vector<std::byte> opened{opened_packet.begin(), opened_packet.end()};
    if (!send_encrypted(socket, opened)) return false;
    for (const auto slot_index : {84U, 85U}) {
        auto refresh = make_refresh_item_packet(2U,
            static_cast<std::uint16_t>(slot_index),
            session.account.storage_items[slot_index]);
        if (!send_encrypted(socket, refresh)) return false;
    }
    session.storage_open = true;
    return true;
}

[[nodiscard]] bool handle_unseal_item(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session) {
    if (request.size() < 16U || !session.entered_world ||
        !session.selected_character.has_value()) return true;
    const auto slot = read_u32(request, 12U);
    if (slot >= 60U) return true;
    auto& character = *session.selected_character;
    if (!is_inventory_slot_unlocked(character.inventory,
            static_cast<std::uint16_t>(slot))) return true;
    const auto item = character.inventory[slot];
    if (item.item_id == 0U || item.item_id >= tables.item_definitions.size())
        return true;
    const auto item_type = tables.item_definitions[item.item_id].item_type;
    std::clog << "[game] unseal request client=" << client_id << " slot=" << slot
              << " item_id=" << item.item_id << " item_type=" << item_type
              << " refine=" << item.refine << " time=" << item.time
              << " character_level=" << character.level
              << " item_level=" << tables.item_definitions[item.item_id].level
              << " bag_slots=" << character.inventory[61U].item_id << ','
              << character.inventory[62U].item_id << ','
              << character.inventory[63U].item_id << std::endl;

    // The Delphi $0224 handler clears an item's seal and immediately invokes
    // UseItem. The client uses this opcode for sealed bags instead of $031D.
    std::array<std::byte, 24U> use_request{};
    write_u32(1U, use_request, 12U);
    write_u32(slot, use_request, 16U);
    if (item_type == 217U) {
        if (!handle_use_inventory_bag(socket, use_request, database_config,
                client_id, tables, session)) return false;
        if (character.inventory[slot].item_id == 0U) return true;
    } else if (item_type == 218U) {
        if (!handle_use_storage_bag(socket, use_request, database_config,
                client_id, tables, session)) return false;
        if (character.inventory[slot].item_id == 0U) return true;
    } else if (item_type == 226U) {
        return handle_open_storage_item(socket, use_request, client_id, tables,
            session);
    }

    auto unsealed = character.inventory[slot];
    const auto& definition = tables.item_definitions[unsealed.item_id];
    const bool sealed = (unsealed.refine & 0xffffU) == 0U &&
        (unsealed.time & 0xffffU) == 0U;
    if (sealed && definition.expires != 0U) {
        const auto expiry = static_cast<std::uint32_t>(std::time(nullptr)) +
            (static_cast<std::uint32_t>(definition.duration) + 2U) * 60U * 60U;
        unsealed.refine = expiry & 0x0000ff00U;
        unsealed.time = (expiry >> 16U) & 0xffffU;
    }
    if (unsealed.item_id != item.item_id || unsealed.app != item.app ||
        unsealed.refine != item.refine || unsealed.time != item.time) {
        const std::vector<database::CharacterItemPlacement> updates{
            {1U, static_cast<std::uint16_t>(slot), unsealed}};
        try {
            database::MysqlConnection database{database_config};
            database.save_character_items(character.id, character.gold, updates);
        } catch (const std::exception& error) {
            OutputDebugStringA((std::string{"Aika item-unseal persistence failed: "} +
                error.what() + "\n").c_str());
            return true;
        }
        character.inventory[slot] = unsealed;
    }
    std::clog << "[game] item unseal client=" << client_id << " slot=" << slot
              << " item_id=" << item.item_id << " item_type=" << item_type
              << " sealed=" << sealed << " used=false" << std::endl;
    auto refresh = make_refresh_item_packet(1U,
        static_cast<std::uint16_t>(slot), character.inventory[slot]);
    return send_encrypted(socket, refresh);
}

[[nodiscard]] bool handle_use_buff_potion(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session, ChannelRuntime& runtime) {
    if (request.size() < 24U || !session.entered_world ||
        !session.selected_character.has_value() || read_u32(request, 12U) != 1U)
        return true;
    auto& character = *session.selected_character;
    if (character.current_hp == 0U) return true;
    const auto slot = read_u32(request, 16U);
    if (slot >= 60U) return true;
    const auto& item = character.inventory[slot];
    if (item.item_id == 0U || item.item_id >= tables.item_definitions.size())
        return true;
    const auto& item_definition = tables.item_definitions[item.item_id];
    if (item_definition.item_type != 702U ||
        (session.account.account_type != 5U && item_definition.level > character.level))
        return true;
    const auto buff_id = item_definition.use_effect;
    if (buff_id == 0U || buff_id >= tables.skill_definitions.size()) return true;
    const auto& buff_definition = tables.skill_definitions[buff_id];
    const auto now = static_cast<std::uint64_t>(std::time(nullptr));
    const auto active = [&tables, now](const auto& buff) {
        const auto id = static_cast<std::size_t>(buff[0]);
        return id != 0U && id < tables.skill_definitions.size() &&
            (buff[1] > now || tables.skill_definitions[id].duration > now - buff[1]);
    };
    const auto has_group = [&character, &tables, &active](const std::uint32_t group) {
        return std::any_of(character.buffs.begin(), character.buffs.end(),
            [&tables, &active, group](const auto& saved) {
                const auto id = static_cast<std::size_t>(saved[0]);
                return active(saved) && tables.skill_definitions[id].index == group;
            });
    };
    const auto item_name_end = std::find(item_definition.name.begin(),
        item_definition.name.end(), '\0');
    const std::string item_name{item_definition.name.begin(), item_name_end};
    const bool is_soup = item_name.starts_with("Sopa");
    const auto skill_name_end = std::find(buff_definition.name.begin(),
        buff_definition.name.end(), '\0');
    const std::string skill_name{buff_definition.name.begin(), skill_name_end};
    const auto incompatible_message = [&] {
        return "Nao e combinavel com [" + skill_name + "].";
    };
    if (is_soup && std::any_of(character.buffs.begin(), character.buffs.end(),
            [&tables, &active](const auto& saved) {
                if (!active(saved)) return false;
                const auto id = static_cast<std::size_t>(saved[0]);
                const auto& name = tables.skill_definitions[id].name;
                return name[0] == 'S' && name[1] == 'o' &&
                    name[2] == 'p' && name[3] == 'a';
            }))
        return send_client_message(socket, incompatible_message(), client_id);
    if (buff_definition.index == 251U && has_group(251U))
        return send_client_message(socket, incompatible_message(), client_id);
    if (buff_definition.index == 298U && has_group(176U)) return true;
    constexpr std::array<std::uint32_t, 5U> battle_groups{
        493U, 494U, 495U, 496U, 497U};
    if (std::find(battle_groups.begin(), battle_groups.end(), buff_definition.index) !=
            battle_groups.end() &&
        std::any_of(battle_groups.begin(), battle_groups.end(),
            [&has_group, &buff_definition](const auto group) {
                return group != buff_definition.index && has_group(group);
            }))
        return send_client_message(socket, incompatible_message(), client_id);

    auto updated_buffs = character.buffs;
    std::size_t occupied{};
    for (auto& saved : updated_buffs) {
        const auto id = static_cast<std::size_t>(saved[0]);
        if (id != 0U && id < tables.skill_definitions.size() &&
            (saved[1] <= now && tables.skill_definitions[id].duration <= now - saved[1]))
            saved = {};
        if (saved[0] != 0U) ++occupied;
    }
    bool add_buff = true;
    if (occupied >= updated_buffs.size()) {
        add_buff = false;
        if (!send_client_message(socket,
                "Nao foi possivel adicionar novos buffs. Limite: 60 Buffs.",
                client_id)) return false;
    } else if (buff_id == 7257U || buff_id == 9133U) {
        add_buff = false;
    } else {
        for (auto& saved : updated_buffs) {
            const auto id = static_cast<std::size_t>(saved[0]);
            if (id < tables.skill_definitions.size() && saved[0] != 0U &&
                tables.skill_definitions[id].index == buff_definition.index)
                saved = {};
        }
        const auto free_slot = std::find_if(updated_buffs.begin(), updated_buffs.end(),
            [](const auto& saved) { return saved[0] == 0U; });
        if (free_slot == updated_buffs.end()) {
            add_buff = false;
        } else {
            *free_slot = {buff_id, now};
        }
    }

    auto updated_item = item;
    if (updated_item.refine > 1U) --updated_item.refine;
    else updated_item = {};
    const std::vector<database::CharacterItemPlacement> updates{
        {1U, static_cast<std::uint16_t>(slot), updated_item}};
    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(character.id, character.gold, updates, {},
            std::nullopt, std::nullopt,
            add_buff ? std::optional{updated_buffs} : std::nullopt);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika buff-potion persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    character.inventory[slot] = updated_item;
    if (add_buff) character.buffs = updated_buffs;
    if (add_buff) {
        std::vector<std::byte> added_buff(24U);
        protocol::PacketHeader header{};
        header.size = static_cast<std::uint16_t>(added_buff.size());
        header.client_index = client_id;
        header.opcode = 0x016fU;
        const auto encoded_header = protocol::encode_header(header);
        std::copy(encoded_header.begin(), encoded_header.end(), added_buff.begin());
        const auto packet = std::span<std::byte>{added_buff};
        write_u32(buff_id, packet, 12U);
        write_u32(static_cast<std::uint32_t>(now + buff_definition.duration), packet, 16U);
        if (!runtime.send_to_visible(session, added_buff) ||
            !runtime.refresh_buffs(session, tables)) return false;
        auto status = make_refresh_status_packet(character, tables);
        if (!send_encrypted(socket, status)) return false;
        auto points = make_refresh_points_packet(character);
        if (!send_encrypted(socket, points)) return false;
        auto hp_mp = make_current_hp_mp_packet(character, client_id, tables);
        if (!send_encrypted(socket, hp_mp)) return false;
    }
    auto refresh = make_refresh_item_packet(1U,
        static_cast<std::uint16_t>(slot), updated_item);
    return send_encrypted(socket, refresh);
}

[[nodiscard]] bool handle_use_buff_item(const SOCKET socket,
        const std::span<const std::byte> request,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session, ChannelRuntime& runtime) {
    if (request.size() < 16U || !session.entered_world ||
        !session.selected_character.has_value()) return true;
    const auto slot = read_u32(request, 12U);
    auto& character = *session.selected_character;
    if (slot >= 60U) return true;
    const auto& item = character.inventory[slot];
    if (item.item_id == 0U || item.item_id >= tables.item_definitions.size() ||
        (item.refine == 0U && item.time == 0U)) return true;
    const auto& item_definition = tables.item_definitions[item.item_id];
    if (item_definition.item_type != 715U && item_definition.item_type != 716U)
        return true;
    const auto buff_id = item_definition.use_effect;
    if (buff_id == 0U || buff_id >= tables.skill_definitions.size() ||
        buff_id == 7257U || buff_id == 9133U) return true;

    const auto& buff_definition = tables.skill_definitions[buff_id];
    const auto has_buff_group = [&character, &tables](const std::uint32_t group) {
        const auto now = static_cast<std::uint64_t>(std::time(nullptr));
        return std::any_of(character.buffs.begin(), character.buffs.end(),
            [&tables, group, now](const auto& buff) {
                const auto id = static_cast<std::size_t>(buff[0]);
                if (id == 0U || id >= tables.skill_definitions.size()) return false;
                const auto duration = static_cast<std::uint64_t>(
                    tables.skill_definitions[id].duration);
                return (buff[1] > now || duration > now - buff[1]) &&
                    tables.skill_definitions[id].index == group;
            });
    };
    const auto duplicate_message = [&buff_definition](const std::string_view prefix) {
        const auto name_end = std::find(buff_definition.name.begin(),
            buff_definition.name.end(), '\0');
        const std::string name{buff_definition.name.begin(), name_end};
        return std::string{prefix} + "[" + name + "].";
    };
    const auto group = buff_definition.index;
    const bool incompatible_buff = item_definition.item_type == 715U
        ? ((group == 285U && has_buff_group(285U)) ||
           (group == 280U && has_buff_group(281U)) ||
           (group == 281U && has_buff_group(280U)) ||
           (group == 305U && has_buff_group(305U)))
        : (group == 251U && has_buff_group(251U));
    if (incompatible_buff)
        return send_client_message(socket,
            duplicate_message("Nao e combinavel com "), client_id);
    if (item_definition.item_type == 716U && buff_id == 8124U &&
        has_buff_group(251U)) return true;

    auto updated_buffs = character.buffs;
    const auto now = static_cast<std::uint64_t>(std::time(nullptr));
    std::size_t occupied{};
    for (std::size_t i = 0U; i < updated_buffs.size(); ++i) {
        auto& saved = updated_buffs[i];
        const auto saved_id = static_cast<std::size_t>(saved[0]);
        if (saved_id != 0U && saved_id < tables.skill_definitions.size() &&
            (saved[1] <= now && tables.skill_definitions[saved_id].duration <= now - saved[1]))
            saved = {};
        if (saved[0] != 0U) ++occupied;
    }
    if (occupied >= updated_buffs.size())
        return send_client_message(socket,
            "Nao foi possivel adicionar novos buffs. Limite: 60 Buffs.", client_id);
    std::optional<std::size_t> free_slot;
    for (std::size_t i = 0U; i < updated_buffs.size(); ++i) {
        auto& saved = updated_buffs[i];
        if (saved[0] == 0U) {
            if (!free_slot.has_value()) free_slot = i;
            continue;
        }
        const auto active_id = static_cast<std::size_t>(saved[0]);
        if (active_id < tables.skill_definitions.size() &&
            tables.skill_definitions[active_id].index == group) {
            saved = {};
            if (!free_slot.has_value()) free_slot = i;
        }
    }
    if (!free_slot.has_value())
        return send_client_message(socket,
            "Nao foi possivel adicionar novos buffs. Limite: 60 Buffs.", client_id);
    updated_buffs[*free_slot] = {buff_id, now};
    try {
        database::MysqlConnection database{database_config};
        database.save_character_buffs(character.id, updated_buffs);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika buff-item persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    character.buffs = updated_buffs;

    std::vector<std::byte> added_buff(24U);
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(added_buff.size());
    header.client_index = client_id;
    header.opcode = 0x016fU;
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), added_buff.begin());
    const auto packet = std::span<std::byte>{added_buff};
    write_u32(buff_id, packet, 12U);
    write_u32(static_cast<std::uint32_t>(now + buff_definition.duration), packet, 16U);
    if (!runtime.send_to_visible(session, added_buff)) return false;
    if (!runtime.refresh_buffs(session, tables)) return false;
    auto status = make_refresh_status_packet(character, tables);
    if (!send_encrypted(socket, status)) return false;
    auto points = make_refresh_points_packet(character);
    if (!send_encrypted(socket, points)) return false;
    auto hp_mp = make_current_hp_mp_packet(character, client_id, tables);
    return send_encrypted(socket, hp_mp);
}

[[nodiscard]] bool expire_timed_character_items(const SOCKET socket,
        const config::DatabaseConfig& database_config,
        const std::uint16_t client_id, const data::GameTables& tables,
        GameSession& session, ChannelRuntime& runtime) {
    if (!session.entered_world || !session.selected_character.has_value()) return true;
    const auto now = static_cast<std::uint32_t>(std::time(nullptr));
    auto updated = *session.selected_character;
    std::vector<database::CharacterItemPlacement> updates;
    std::vector<std::uint16_t> buffs_to_remove;
    std::vector<std::string> expired_names;
    bool equipment_changed{};
    bool storage_changed{};

    const auto expired = [&tables, now](const database::CharacterItem& item,
            const bool equipment) {
        if (item.item_id == 0U || item.item_id >= tables.item_definitions.size() ||
            tables.item_definitions[item.item_id].expires == 0U ||
            is_expired_equipment_marker(item, tables)) return false;
        if (equipment && item.time == 0U) return false;
        if ((item.refine & 0xffffU) == 0U && (item.time & 0xffffU) == 0U)
            return false; // Delphi's IsSealed marker.
        const auto expire_at = ((item.time & 0xffffU) << 16U) |
            (item.refine & 0xff00U);
        return now > expire_at;
    };
    const auto item_name = [&tables](const database::CharacterItem& item) {
        if (item.item_id >= tables.item_definitions.size()) return std::string{};
        const auto& name = tables.item_definitions[item.item_id].name;
        return std::string{name.begin(), std::find(name.begin(), name.end(), '\0')};
    };

    for (std::uint16_t slot = 0U; slot < updated.inventory.size(); ++slot) {
        auto& item = updated.inventory[slot];
        if (!expired(item, false)) continue;
        const auto& definition = tables.item_definitions[item.item_id];
        expired_names.push_back(item_name(item));
        if (definition.item_type == 716U && definition.use_effect != 0U)
            buffs_to_remove.push_back(definition.use_effect);
        if (item_equip_slot(definition) == 9) {
            item.time = 0xffffU;
        } else if (definition.class_id >= 100U && definition.class_id <= 104U) {
            item.min = 0xffU;
            item.max = 0xffU;
        } else {
            item = {};
        }
        updates.push_back({1U, slot, item});
    }
    for (std::uint16_t slot = 0U; slot < updated.equipment.size(); ++slot) {
        auto& item = updated.equipment[slot];
        if (!expired(item, true)) continue;
        const auto& definition = tables.item_definitions[item.item_id];
        expired_names.push_back(item_name(item));
        if (item_equip_slot(definition) == 9) {
            item.time = 0xffffU;
        } else if (definition.class_id >= 100U && definition.class_id <= 104U) {
            item.min = 0xffU;
            item.max = 0xffU;
        } else {
            item = {};
        }
        updates.push_back({0U, slot, item});
        equipment_changed = true;
    }
    auto updated_storage = session.account.storage_items;
    for (std::uint16_t slot = 0U; slot < 84U; ++slot) {
        auto& item = updated_storage[slot];
        if (!expired(item, false)) continue;
        const auto& definition = tables.item_definitions[item.item_id];
        expired_names.push_back(item_name(item));
        if (item_equip_slot(definition) == 9) {
            item.time = 0xffffU;
        } else if (definition.class_id >= 100U && definition.class_id <= 104U) {
            item.min = 0xffU;
            item.max = 0xffU;
        } else {
            item = {};
        }
        updates.push_back({2U, slot, item});
        storage_changed = true;
    }
    const auto now64 = static_cast<std::uint64_t>(now);
    for (const auto& buff : updated.buffs) {
        const auto index = static_cast<std::size_t>(buff[0]);
        if (index == 0U || index >= tables.skill_definitions.size()) continue;
        const auto created_at = buff[1];
        const auto duration = static_cast<std::uint64_t>(
            tables.skill_definitions[index].duration);
        if (created_at <= now64 && duration < now64 - created_at)
            buffs_to_remove.push_back(static_cast<std::uint16_t>(index));
    }
    if (updates.empty() && buffs_to_remove.empty()) return true;

    std::sort(buffs_to_remove.begin(), buffs_to_remove.end());
    buffs_to_remove.erase(std::unique(buffs_to_remove.begin(), buffs_to_remove.end()),
        buffs_to_remove.end());
    for (auto& buff : updated.buffs)
        if (std::binary_search(buffs_to_remove.begin(), buffs_to_remove.end(), buff[0]))
            buff = {};
    try {
        database::MysqlConnection database{database_config};
        database.save_character_items(updated.id, updated.gold, updates,
            buffs_to_remove, std::nullopt, std::nullopt, std::nullopt,
            std::nullopt, {}, {}, std::nullopt, {}, storage_changed
                ? std::optional<std::uint32_t>{session.account.id} : std::nullopt);
    } catch (const std::exception& error) {
        OutputDebugStringA((std::string{"Aika item-expiration persistence failed: "} +
            error.what() + "\n").c_str());
        return true;
    }
    if (!runtime.replace_character(session, updated)) return false;
    if (storage_changed) session.account.storage_items = updated_storage;

    for (const auto& update : updates) {
        auto refresh = make_refresh_item_packet(update.slot_type, update.slot, update.item);
        if (!send_encrypted(socket, refresh)) return false;
    }
    for (const auto& name : expired_names)
        if (!send_client_message(socket, "O item [" + name + "] expirou.", client_id))
            return false;
    if (!buffs_to_remove.empty()) {
        if (!runtime.refresh_buffs(session, tables)) return false;
        auto hp_mp = make_current_hp_mp_packet(updated, client_id, tables);
        auto status = make_refresh_status_packet(updated, tables);
        auto points = make_refresh_points_packet(updated);
        if (!send_encrypted(socket, hp_mp) || !send_encrypted(socket, status) ||
            !send_encrypted(socket, points)) return false;
    }
    if (equipment_changed) {
        if (!runtime.refresh_equipment_status(session, tables) ||
            !runtime.refresh_player_spawn(session, tables)) return false;
    }
    return true;
}

void serve_game_client(const SOCKET socket, const config::DatabaseConfig& database_config,
        const config::GameRules& game_rules,
        const std::uint16_t client_id, const data::GameTables* tables,
        ChannelRuntime& runtime, auth::LoginGrantRegistry& login_grants) {
    AccountPresence presence{database_config};
    DWORD timeout_ms = 1000U;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    protocol::FrameDecoder decoder;
    std::vector<std::byte> pending;
    std::array<char, 4096> buffer{};
    bool first = true;
    auto session = std::make_shared<GameSession>(socket, client_id);
    struct RuntimeCleanup final {
        ChannelRuntime& runtime;
        GameSession& session;
        ~RuntimeCleanup() { runtime.leave(session); }
    } cleanup{runtime, *session};

    while (true) {
        runtime.tick_mob_respawns();
        runtime.tick_mob_ai(*tables);
        if (!expire_timed_character_items(socket, database_config, client_id,
                *tables, *session, runtime)) return;
        const auto received = recv(socket, buffer.data(), static_cast<int>(buffer.size()), 0);
        if (received == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT) {
            const auto idle_limit = session->authenticated
                ? std::chrono::minutes{5} : std::chrono::seconds{15};
            if (!session->entered_world &&
                std::chrono::steady_clock::now() - session->last_packet_at >= idle_limit) {
                std::clog << "[game] handshake timeout client=" << client_id
                          << " stage=" << (session->authenticated ? "character-select" : "login")
                          << " buffered=" << (pending.size() + decoder.buffered_bytes())
                          << std::endl;
                return;
            }
            continue;
        }
        if (received <= 0) {
            std::clog << "[game] connection closed client=" << client_id
                      << " stage=" << (session->entered_world ? "world" :
                          session->authenticated ? "character-select" : "login")
                      << std::endl;
            return;
        }
        session->last_packet_at = std::chrono::steady_clock::now();
        const auto* data = reinterpret_cast<const std::byte*>(buffer.data());
        pending.insert(pending.end(), data, data + received);
        if (first && pending.size() < 6U) continue;
        if (first) {
            // PlayerThread.pas removes the first four bytes on the first game
            // packet whenever that recv is larger than 60 bytes. Match that
            // legacy rule; encrypted header fields cannot reliably identify
            // this wrapper before decryption.
            const bool removed_legacy_prefix = pending.size() > 60U;
            const auto received_bytes = pending.size();
            if (removed_legacy_prefix)
                pending.erase(pending.begin(), pending.begin() + 4);
            const auto declared_size = pending.size() >= 2U
                ? static_cast<std::size_t>(read_u16(pending, 0U)) : 0U;
            std::clog << "[game] initial framing client=" << client_id
                      << " removed_legacy_prefix="
                      << (removed_legacy_prefix ? "yes" : "no")
                      << " received_bytes=" << received_bytes
                      << " declared_bytes=" << declared_size << std::endl;
            first = false;
        }
        if (decoder.feed(pending) != protocol::FrameStatus::accepted) {
            std::clog << "[game] invalid frame data client=" << client_id << std::endl;
            return;
        }
        pending.clear();
        while (true) {
            auto result = decoder.next_frame();
            if (result.status == protocol::FrameStatus::need_more_data) break;
            if (result.status != protocol::FrameStatus::frame_ready) {
                std::clog << "[game] incomplete or invalid frame client="
                          << client_id << std::endl;
                return;
            }
            if (!session->authenticated) {
                if (!handle_login(socket, result.bytes, database_config, client_id,
                        presence, *session, login_grants)) return;
                continue;
            }
            (void)protocol::decrypt_frame(result.bytes);
            const auto header = protocol::decode_header(result.bytes);
            if (!header) {
                std::clog << "[game] invalid packet header client="
                          << client_id << std::endl;
                return;
            }
            if (session->entered_world && session->world_packet_debug_logged < 48U) {
                ++session->world_packet_debug_logged;
                std::clog << "[game] world client packet client=" << client_id
                          << " opcode=0x" << std::hex << header.header.opcode << std::dec
                          << " bytes=" << result.bytes.size() << std::endl;
            }
            const auto opcode = header.header.opcode;
            const bool high_rate_world_packet = opcode == movement_opcode ||
                opcode == enter_world_opcode || opcode == rotation_opcode ||
                opcode == update_action_opcode || opcode == server_time_request_opcode ||
                opcode == server_ping_request_opcode || opcode == ping_reply_opcode ||
                opcode == remove_mob_opcode;
            if (session->entered_world && session->interaction_debug_logged < 100U &&
                (opcode == open_npc_opcode || opcode == buy_npc_item_opcode ||
                 opcode == sell_npc_item_opcode || opcode == use_item_opcode ||
                 opcode == move_item_opcode || opcode == receive_event_item_opcode ||
                 opcode == 0x033aU || opcode == repair_items_opcode ||
                 !high_rate_world_packet)) {
                ++session->interaction_debug_logged;
                std::clog << "[game] interaction packet client=" << client_id
                          << " opcode=0x" << std::hex << opcode << std::dec
                          << " bytes=" << result.bytes.size();
                if (result.bytes.size() >= 16U)
                    std::clog << " field12=" << read_u32(result.bytes, 12U);
                if (result.bytes.size() >= 20U)
                    std::clog << " field16=" << read_u32(result.bytes, 16U);
                if (result.bytes.size() >= 24U)
                    std::clog << " field20=" << read_u32(result.bytes, 20U);
                std::clog << " opened_npc=" << session->opened_npc
                          << " opened_option=" << session->opened_npc_option
                          << " visible_npcs=" << session->visible_mobs.size()
                          << " raw=" << std::hex;
                const auto bytes_to_log = (std::min<std::size_t>)(
                    result.bytes.size(), 32U);
                for (std::size_t byte = 0U; byte < bytes_to_log; ++byte) {
                    if (byte != 0U) std::clog << ' ';
                    std::clog << std::setw(2) << std::setfill('0')
                              << std::to_integer<unsigned>(result.bytes[byte]);
                }
                std::clog << std::dec << std::setfill(' ') << std::endl;
            }
            if (!session->entered_world) {
                std::clog << "[game] pre-world packet client=" << client_id
                          << " opcode=0x" << std::hex << header.header.opcode << std::dec
                          << " bytes=" << result.bytes.size() << std::endl;
            }
            if (header.header.opcode == numeric_token_opcode) {
                std::clog << "[game] character selection packet client="
                          << client_id << " bytes=" << result.bytes.size() << std::endl;
            }
            if (header.header.opcode == create_character_opcode) {
                if (!handle_create_character(socket, result.bytes, database_config,
                        client_id, *tables, *session)) return;
                continue;
            }
            if (header.header.opcode == request_delete_character_opcode) {
                if (!handle_request_character_deletion(socket, result.bytes,
                        database_config, game_rules, client_id, *session)) return;
                continue;
            }
            if (header.header.opcode == delete_character_opcode) {
                if (!handle_delete_character(socket, result.bytes, database_config,
                        client_id, *session)) return;
                continue;
            }
            if (header.header.opcode == learn_skill_opcode) {
                if (!handle_learn_skill(socket, result.bytes, database_config,
                        client_id, *tables, *session)) return;
                continue;
            }
            if (header.header.opcode == reset_skills_opcode) {
                if (!handle_reset_skills(socket, database_config, client_id,
                        *tables, *session)) return;
                continue;
            }
            if (header.header.opcode == remove_buff_opcode) {
                if (!handle_remove_buff(socket, result.bytes, database_config,
                        client_id, *tables, *session, runtime)) return;
                continue;
            }
            if (header.header.opcode == make_item_opcode) {
                if (!handle_make_item(socket, result.bytes, database_config,
                        client_id, *tables, *session)) return;
                continue;
            }
            if (header.header.opcode == delete_item_opcode) {
                if (!handle_delete_item(socket, result.bytes, database_config,
                        client_id, *tables, *session, runtime)) return;
                continue;
            }
            if (header.header.opcode == group_item_opcode) {
                if (!handle_group_item(socket, result.bytes, database_config,
                        *tables, *session)) return;
                continue;
            }
            if (header.header.opcode == ungroup_item_opcode) {
                if (!handle_ungroup_item(socket, result.bytes, database_config,
                        *tables, *session, client_id)) return;
                continue;
            }
            if (header.header.opcode == unseal_item_opcode) {
                if (!handle_unseal_item(socket, result.bytes, database_config,
                        client_id, *tables, *session)) return;
                continue;
            }
            if (header.header.opcode == use_item_opcode) {
                const auto use_type = result.bytes.size() >= 16U
                    ? read_u32(result.bytes, 12U) : 0xffffffffU;
                if (result.bytes.size() >= 20U) {
                    const auto slot = read_u32(result.bytes, 16U);
                    const auto item_id = use_type == 1U && slot < 60U &&
                            session->selected_character.has_value()
                        ? session->selected_character->inventory[slot].item_id : 0U;
                    const auto item_type = item_id < tables->item_definitions.size()
                        ? tables->item_definitions[item_id].item_type : 0U;
                    const auto use_effect = item_id < tables->item_definitions.size()
                        ? tables->item_definitions[item_id].use_effect : 0U;
                    std::clog << "[game] item use resolved client=" << client_id
                              << " use_type=" << use_type << " slot=" << slot
                              << " item_id=" << item_id << " item_type=" << item_type
                              << " use_effect=" << use_effect << std::endl;
                }
                if (use_type == 1U) {
                    std::uint16_t item_type{};
                    if (result.bytes.size() >= 20U && session->selected_character.has_value()) {
                        const auto slot = read_u32(result.bytes, 16U);
                        if (slot < 60U) {
                            const auto item_id = session->selected_character->inventory[slot].item_id;
                            if (item_id < tables->item_definitions.size())
                                item_type = tables->item_definitions[item_id].item_type;
                        }
                    }
                    if (item_type == 234U || item_type == 717U) {
                        if (!handle_use_gold_coin(socket, result.bytes,
                                database_config, client_id, *tables, *session)) return;
                    } else if (item_type == 239U) {
                        if (!handle_use_cash_coin(socket, result.bytes,
                                database_config, *tables, *session)) return;
                    } else if (item_type == 702U) {
                        if (!handle_use_buff_potion(socket, result.bytes,
                                database_config, client_id, *tables, *session, runtime))
                            return;
                    } else if (item_type == 404U || item_type == 704U) {
                        if (!handle_use_exp_item(socket, result.bytes,
                                database_config, client_id, *tables, *session)) return;
                    } else if (item_type == 205U) {
                        if (!handle_use_recipe_item(socket, result.bytes,
                                database_config, client_id, *tables, *session)) return;
                    } else if (item_type == 217U) {
                        if (!handle_use_inventory_bag(socket, result.bytes,
                                database_config, client_id, *tables, *session)) return;
                    } else if (item_type == 218U) {
                        if (!handle_use_storage_bag(socket, result.bytes,
                                database_config, client_id, *tables, *session)) return;
                    } else if (item_type == 226U) {
                        if (!handle_open_storage_item(socket, result.bytes,
                                client_id, *tables, *session)) return;
                    } else if (item_type == 714U && result.bytes.size() >= 24U &&
                        session->selected_character.has_value()) {
                        const auto slot = read_u32(result.bytes, 16U);
                        if (slot < 60U) {
                            const auto item_id = session->selected_character->inventory[slot].item_id;
                            if (item_id < tables->item_definitions.size() &&
                                (tables->item_definitions[item_id].use_effect == 39U ||
                                 tables->item_definitions[item_id].use_effect == 41U ||
                                 (tables->item_definitions[item_id].use_effect >= 42U &&
                                  tables->item_definitions[item_id].use_effect <= 45U) ||
                                 (tables->item_definitions[item_id].use_effect >= 137U &&
                                  tables->item_definitions[item_id].use_effect <= 142U) ||
                                 tables->item_definitions[item_id].use_effect == 1U ||
                                 tables->item_definitions[item_id].use_effect == 5289U ||
                                 tables->item_definitions[item_id].use_effect == 1133U ||
                                 (tables->item_definitions[item_id].use_effect >= 1138U &&
                                  tables->item_definitions[item_id].use_effect <= 1145U) ||
                                 (tables->item_definitions[item_id].use_effect >= 1493U &&
                                  tables->item_definitions[item_id].use_effect <= 1500U) ||
                                 tables->item_definitions[item_id].use_effect == 1105U ||
                                 tables->item_definitions[item_id].use_effect == 1854U ||
                                 tables->item_definitions[item_id].use_effect == 1856U ||
                                 tables->item_definitions[item_id].use_effect == 1857U ||
                                 tables->item_definitions[item_id].use_effect == 18855U) &&
                                !handle_use_equipment_set_box(socket, result.bytes,
                                    database_config, client_id, *tables, *session)) return;
                            if (item_id < tables->item_definitions.size() &&
                                (tables->item_definitions[item_id].use_effect == 357U ||
                                 (tables->item_definitions[item_id].use_effect >= 666U &&
                                  tables->item_definitions[item_id].use_effect <= 675U) ||
                                 tables->item_definitions[item_id].use_effect == 1787U ||
                                 (tables->item_definitions[item_id].use_effect >= 1858U &&
                                  tables->item_definitions[item_id].use_effect <= 1860U)) &&
                                !handle_use_reward_box(socket, result.bytes,
                                    database_config, client_id, *tables, *session)) return;
                        }
                    } else if (item_type == 705U && result.bytes.size() >= 24U &&
                        session->selected_character.has_value()) {
                        const auto slot = read_u32(result.bytes, 16U);
                        if (slot < 60U) {
                            const auto item_id = session->selected_character->inventory[slot].item_id;
                            if (item_id < tables->item_definitions.size() &&
                                tables->item_definitions[item_id].use_effect == 1089U &&
                                !handle_use_equipment_set_box(socket, result.bytes,
                                    database_config, client_id, *tables, *session)) return;
                            if (item_id < tables->item_definitions.size() &&
                                (tables->item_definitions[item_id].use_effect == 10766U ||
                                 tables->item_definitions[item_id].use_effect == 10767U ||
                                 tables->item_definitions[item_id].use_effect == 10768U) &&
                                !handle_use_title_box(socket, result.bytes,
                                    database_config, client_id, *tables, *session)) return;
                            if (item_id < tables->item_definitions.size() &&
                                tables->item_definitions[item_id].use_effect == 198U &&
                                !handle_use_random_gold_box(socket, result.bytes,
                                    database_config, client_id, *tables, *session)) return;
                            if (item_id < tables->item_definitions.size() &&
                                (tables->item_definitions[item_id].use_effect == 1U ||
                                 tables->item_definitions[item_id].use_effect == 98U ||
                                 tables->item_definitions[item_id].use_effect == 629U ||
                                 tables->item_definitions[item_id].use_effect == 910U ||
                                 tables->item_definitions[item_id].use_effect == 950U ||
                                 tables->item_definitions[item_id].use_effect == 1030U ||
                                 tables->item_definitions[item_id].use_effect == 1130U ||
                                 tables->item_definitions[item_id].use_effect == 16020U ||
                                 (tables->item_definitions[item_id].use_effect >= 16000U &&
                                  tables->item_definitions[item_id].use_effect <= 16004U)) &&
                                !handle_use_reward_box(socket, result.bytes,
                                    database_config, client_id, *tables, *session)) return;
                        }
                    } else if (!handle_use_hp_mp_potion(socket, result.bytes,
                            database_config, client_id, *tables, *session, runtime)) {
                        return;
                    }
                } else if (!handle_repair_item(socket, result.bytes,
                        database_config, *tables, *session, client_id)) {
                    return;
                }
                continue;
            }
            if (header.header.opcode == use_buff_item_opcode) {
                if (!handle_use_buff_item(socket, result.bytes, database_config,
                        client_id, *tables, *session, runtime)) return;
                continue;
            }
            if (header.header.opcode == numeric_token_opcode) {
                const auto handled = handle_numeric_token(socket, result.bytes, database_config,
                    client_id, *tables, *session);
                std::clog << "[game] character selection result client=" << client_id
                          << "=" << (handled ? "handled" : "rejected") << std::endl;
                if (!handled) return;
                continue;
            }
            if (header.header.opcode == receive_event_item_opcode) {
                if (!handle_receive_event_items(socket, result.bytes,
                        database_config, client_id, *tables, *session)) return;
                continue;
            }
            if (header.header.opcode == enter_world_opcode) {
                const auto entered = handle_enter_world(socket, client_id, *tables, session, runtime);
                std::clog << "[game] enter-world client=" << client_id
                          << " result=" << (entered ? "accepted" : "rejected")
                          << std::endl;
                if (!entered) return;
                continue;
            }
            if (header.header.opcode == attack_target_opcode) {
                if (!runtime.attack_target(*session, result.bytes, *tables)) return;
                continue;
            }
            if (header.header.opcode == open_npc_opcode && result.bytes.size() >= 20U) {
                const auto npc_option = read_u32(result.bytes, 16U);
                if (npc_option == 0x23U || npc_option == 0x41U) {
                    if (!runtime.apply_npc_buff_option(*session, result.bytes,
                            npc_option, *tables)) return;
                    continue;
                }
            }
            if (header.header.opcode == open_npc_opcode) {
                if (!runtime.open_npc(*session, result.bytes, *tables)) return;
                if (session->interaction_debug_logged < 100U)
                    std::clog << "[game] npc interaction state client=" << client_id
                              << " opened_npc=" << session->opened_npc
                              << " opened_option=" << session->opened_npc_option
                              << std::endl;
                continue;
            }
            if (header.header.opcode == buy_npc_item_opcode) {
                if (!runtime.buy_npc_item(*session, result.bytes, *tables)) return;
                continue;
            }
            if (header.header.opcode == sell_npc_item_opcode) {
                if (!runtime.sell_npc_item(*session, result.bytes, *tables)) return;
                continue;
            }
            if (header.header.opcode == repair_items_opcode) {
                if (!runtime.repair_items(*session, result.bytes, *tables)) return;
                continue;
            }
            if (header.header.opcode == close_npc_option_opcode) {
                const auto signal_data = result.bytes.size() >= 16U
                    ? read_u32(result.bytes, 12U) : 0U;
                std::clog << "[game] close-signal client=" << client_id
                          << " data=" << signal_data
                          << " opened_npc=" << session->opened_npc
                          << " opened_option=" << session->opened_npc_option
                          << std::endl;
                session->opened_npc = 0U;
                session->opened_npc_option = 0U;
                continue;
            }
            if (header.header.opcode == movement_opcode) {
                const auto previous_x = session->selected_character.has_value()
                    ? session->selected_character->position_x : 0.0F;
                const auto previous_y = session->selected_character.has_value()
                    ? session->selected_character->position_y : 0.0F;
                const auto moved = runtime.move(*session, result.bytes, *tables);
                if (session->movement_debug_logged < 20U) {
                    ++session->movement_debug_logged;
                    const auto destination_x = result.bytes.size() >= 16U
                        ? std::bit_cast<float>(read_u32(result.bytes, 12U)) : 0.0F;
                    const auto destination_y = result.bytes.size() >= 20U
                        ? std::bit_cast<float>(read_u32(result.bytes, 16U)) : 0.0F;
                    std::clog << "[game] movement client=" << client_id
                              << " result=" << (moved ? "accepted" : "rejected")
                              << " bytes=" << result.bytes.size()
                              << " previous=" << previous_x << ',' << previous_y
                              << " destination=" << destination_x << ',' << destination_y
                              << " delta=" << (destination_x - previous_x) << ','
                              << (destination_y - previous_y)
                              << " type=" << (result.bytes.size() > 26U
                                  ? std::to_integer<unsigned>(result.bytes[26U]) : 255U)
                              << " speed=" << (result.bytes.size() > 27U
                                  ? std::to_integer<unsigned>(result.bytes[27U]) : 0U)
                              << " hp=" << (session->selected_character.has_value()
                                  ? session->selected_character->current_hp : 0U)
                              << std::endl;
                }
                continue;
            }
            if (header.header.opcode == revive_player_opcode) {
                std::clog << "[game] revive request client=" << client_id
                          << " entered_world=" << (session->entered_world ? "yes" : "no")
                          << " hp_before=" << (session->selected_character.has_value()
                              ? session->selected_character->current_hp : 0U)
                          << std::endl;
                if (!runtime.revive_player(*session, *tables)) return;
                std::clog << "[game] revive processed client=" << client_id
                          << " hp_after=" << (session->selected_character.has_value()
                              ? session->selected_character->current_hp : 0U)
                          << std::endl;
                continue;
            }
            if (header.header.opcode == update_action_opcode) {
                (void)runtime.relay_player_action(*session, result.bytes,
                    update_action_opcode);
                continue;
            }
            if (header.header.opcode == rotation_opcode) {
                if (session->rotation_debug_logged < 5U) {
                    ++session->rotation_debug_logged;
                    const auto rotation = result.bytes.size() >= 16U
                        ? read_u32(result.bytes, 12U) : 0U;
                    std::clog << "[game] rotation client=" << client_id
                              << " value=" << rotation
                              << " bytes=" << result.bytes.size() << std::endl;
                }
                (void)runtime.update_rotation(*session, result.bytes);
                continue;
            }
            if (header.header.opcode == cancel_skill_launching_opcode) {
                (void)runtime.relay_player_action(*session, result.bytes,
                    cancel_skill_launching_opcode);
                continue;
            }
            if (header.header.opcode == chat_opcode) {
                if (session->entered_world)
                    (void)runtime.chat(*session, result.bytes);
                continue;
            }
            if (header.header.opcode == server_time_request_opcode) {
                (void)runtime.request_server_time(*session);
                continue;
            }
            if (header.header.opcode == server_ping_request_opcode) {
                (void)runtime.request_server_ping(*session);
                continue;
            }
            if (header.header.opcode == move_item_opcode) {
                if (result.bytes.size() >= 20U) {
                    const auto destination_type = read_u16(result.bytes, 12U);
                    const auto source_type = read_u16(result.bytes, 16U);
                    if (source_type == 2U || destination_type == 2U) {
                        if (!handle_storage_item_move(socket, result.bytes,
                                database_config, *tables, *session)) return;
                        continue;
                    }
                }
                if (!handle_inventory_move(socket, result.bytes, database_config,
                        *tables, *session,
                        [&runtime, &session,
                         destination_type = read_u16(result.bytes, 12U),
                         destination_slot = read_u16(result.bytes, 14U),
                         source_type = read_u16(result.bytes, 16U),
                         source_slot = read_u16(result.bytes, 18U)] {
                            return runtime.move_character_items(*session, source_type,
                                source_slot, destination_type, destination_slot);
                        }, [&runtime, &session,
                         destination_slot = read_u16(result.bytes, 14U),
                         source_slot = read_u16(result.bytes, 18U)](
                                const std::uint16_t source_quantity,
                                const std::uint16_t destination_quantity,
                                const std::uint16_t new_source_quantity,
                                const std::uint16_t new_destination_quantity) {
                            return runtime.merge_character_stacks(*session, source_slot,
                                destination_slot, source_quantity, destination_quantity,
                                new_source_quantity, new_destination_quantity);
                        }, [&runtime, &session, tables] {
                            return runtime.refresh_equipment_status(*session, *tables);
                        }, [&runtime, &session, tables] {
                            return runtime.refresh_player_spawn(*session, *tables);
                        })) return;
                continue;
            }
            if (header.header.opcode == change_item_bar_opcode) {
                if (result.bytes.size() < 24U) continue;
                const auto destination_slot = read_u32(result.bytes, 12U);
                const auto source_type = read_u32(result.bytes, 16U);
                const auto source_index = read_u32(result.bytes, 20U);
                if (runtime.change_item_bar(*session, destination_slot,
                        source_type, source_index).has_value()) {
                    const auto response = make_item_bar_packet(destination_slot,
                        source_type, source_index);
                    std::vector<std::byte> output(response.begin(), response.end());
                    if (!send_encrypted(socket, output)) return;
                }
                continue;
            }
            if (header.header.opcode == status_point_opcode) {
                if (result.bytes.size() < 20U) continue;
                const auto status_index = read_u32(result.bytes, 12U);
                const auto amount = read_u32(result.bytes, 16U);
                const auto updated = runtime.allocate_status_points(*session,
                    status_index, amount);
                if (updated.has_value()) {
                    auto status = make_refresh_status_packet(*updated, *tables);
                    auto points = make_refresh_points_packet(*updated);
                    auto hp_mp = make_current_hp_mp_packet(*updated, client_id, *tables);
                    if (!send_encrypted(socket, status) ||
                        !send_encrypted(socket, points) ||
                        !send_encrypted(socket, hp_mp)) return;
                }
                continue;
            }
            // Delphi ignores unrecognized opcodes; keep the session alive while
            // their handlers are migrated.
            continue;
        }
    }
}

} // namespace

GameChannels::GameChannels(config::ServerConfig config,
        std::vector<data::ServerEntry> servers, const data::GameTables& tables,
        const data::WorldData& world_data,
        std::shared_ptr<auth::LoginGrantRegistry> login_grants)
    : config_{std::move(config)}, servers_{std::move(servers)}, tables_{&tables},
      world_data_{&world_data}, login_grants_{std::move(login_grants)} {
    if (login_grants_ == nullptr)
        throw std::invalid_argument{"Login grant registry is required"};
}

GameChannels::~GameChannels() { stop(); }

void GameChannels::start() {
    if (!listeners_.empty()) throw std::logic_error{"Game channels are already running"};
    std::unordered_set<std::string> bound_addresses;
    const auto channel_count = std::min<std::size_t>(config_.channels, servers_.size());
    for (std::size_t i = 0U; i < channel_count; ++i) {
        const auto& server = servers_[i];
        if (server.ip.empty() || !bound_addresses.insert(server.ip).second) continue;
        auto listener = std::make_unique<network::TcpListener>();
        auto runtime = std::make_shared<ChannelRuntime>(config_.mysql, *world_data_,
            config_.rules.experience_multiplier);
        auto login_grants = login_grants_;
        listener->start(server.ip, 8822U, 512U,
            [database = config_.mysql, rules = config_.rules,
             bind_address = server.ip,
             tables = tables_, runtime, login_grants](const SOCKET socket) {
                auto value = next_client_id.fetch_add(1U);
                if (value == 0U || value > 65535U) {
                    next_client_id.store(2U);
                    value = 1U;
                }
                std::clog << "[game] session accepted client=" << value
                          << " channel=" << bind_address << ":8822" << std::endl;
                serve_game_client(socket, database, rules,
                    static_cast<std::uint16_t>(value), tables, *runtime,
                    *login_grants);
            });
        listeners_.push_back(std::move(listener));
    }
    if (listeners_.empty()) throw std::runtime_error{"Server list contains no bindable channel addresses"};
}

void GameChannels::stop() noexcept {
    for (auto& listener : listeners_) listener->stop();
    listeners_.clear();
}

} // namespace aika::server
