#include "aika/config/runtime_layout.hpp"

#include <array>
#include <system_error>
#include <string_view>
#include <utility>

namespace aika::config {

RuntimeLayout::RuntimeLayout(std::filesystem::path server_root)
    : root_{std::filesystem::absolute(std::move(server_root)).lexically_normal()} {}

const std::filesystem::path& RuntimeLayout::root() const noexcept {
    return root_;
}

std::filesystem::path RuntimeLayout::config_file() const {
    return root_ / "AikaServer.ini";
}

std::filesystem::path RuntimeLayout::server_list_file() const {
    return root_ / "SL.bin";
}

std::filesystem::path RuntimeLayout::data_directory() const {
    return root_ / "Data";
}

std::filesystem::path RuntimeLayout::npc_directory() const {
    return root_ / "NPCs";
}

std::filesystem::path RuntimeLayout::npc_directory(
    const std::filesystem::path& override_path) const {
    return override_path.empty() ? npc_directory() :
        std::filesystem::absolute(override_path).lexically_normal();
}

std::vector<MissingAsset> RuntimeLayout::missing_boot_assets(
    const std::filesystem::path& npc_override) const {
    static constexpr std::array<std::string_view, 27> required_data_files{
        "ItemList.bin",
        "SkillData.bin",
        "SetItem.bin",
        "Conjunts.bin",
        "ReinforceW01.bin",
        "ReinforceA01.bin",
        "Reinforce3.bin",
        "Reinforce2.bin",
        "PI.bin",
        "ExpList.bin",
        "PranExpList.bin",
        "Quest.bin",
        "Quest/Quests.csv",
        "Title.bin",
        "Drops/Monsters_0_20_DropList.csv",
        "Drops/Monsters_21_40_DropList.csv",
        "Drops/Monsters_41_60_DropList.csv",
        "Drops/Monsters_61_80_DropList.csv",
        "Drops/Monsters_81_99_DropList.csv",
        "Drops/Buto_DropList.csv",
        "Drops/CroshuAzul_DropList.csv",
        "Drops/Penza_DropList.csv",
        "Drops/Planta_DropList.csv",
        "Drops/Verit_DropList.csv",
        "Drops/DropAdicional01_DropList.csv",
        "Drops/DropAdicional02_DropList.csv",
        "Recipes.bin",
    };

    std::vector<MissingAsset> missing;
    const auto require_file = [&missing](
        const std::string logical_name,
        const std::filesystem::path& path) {
        std::error_code error;
        if (!std::filesystem::is_regular_file(path, error) || error) {
            missing.push_back({logical_name, path});
        }
    };

    require_file("AikaServer.ini", config_file());
    require_file("SL.bin", server_list_file());
    for (const auto relative : required_data_files) {
        require_file(std::string{relative}, data_directory() / relative);
    }
    require_file("MakeItems.csv", data_directory() / "MakeItems.csv");
    require_file("MakeItemsIngredients.csv", data_directory() / "MakeItemsIngredients.csv");
    require_file("NPCOptionsText.bin", data_directory() / "NPCOptionsText.bin");
    require_file("Map.bin", data_directory() / "Map.bin");
    require_file("ScrollPos.bin", data_directory() / "ScrollPos.bin");
    require_file("MonsterListCSV.csv", data_directory() / "MonsterListCSV.csv");

    std::error_code npc_error;
    const auto npcs = npc_directory(npc_override);
    bool has_npc_file = false;
    if (std::filesystem::is_directory(npcs, npc_error) && !npc_error) {
        for (std::filesystem::directory_iterator it{npcs, npc_error}, end;
             !npc_error && it != end; it.increment(npc_error)) {
            if (it->is_regular_file(npc_error) && !npc_error &&
                it->path().extension() == ".npc") {
                has_npc_file = true;
                break;
            }
        }
    }
    if (!has_npc_file) {
        missing.push_back({"NPCs/*.npc directory", npcs});
    }
    return missing;
}

} // namespace aika::config
