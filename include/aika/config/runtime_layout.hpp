#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace aika::config {

struct MissingAsset final {
    std::string logical_name;
    std::filesystem::path path;
};

class RuntimeLayout final {
public:
    explicit RuntimeLayout(std::filesystem::path server_root);

    [[nodiscard]] const std::filesystem::path& root() const noexcept;
    [[nodiscard]] std::filesystem::path config_file() const;
    [[nodiscard]] std::filesystem::path server_list_file() const;
    [[nodiscard]] std::filesystem::path data_directory() const;
    [[nodiscard]] std::filesystem::path npc_directory() const;
    [[nodiscard]] std::filesystem::path npc_directory(
        const std::filesystem::path& override_path) const;

    // Returns all known boot assets that are absent. It does not read or
    // modify any game data.
    [[nodiscard]] std::vector<MissingAsset> missing_boot_assets(
        const std::filesystem::path& npc_override = {}) const;

private:
    std::filesystem::path root_;
};

} // namespace aika::config
