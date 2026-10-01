#include "aika/config/runtime_layout.hpp"
#include "aika/config/server_config.hpp"
#include "aika/data/game_tables.hpp"
#include "aika/data/server_list.hpp"
#include "aika/data/world_data.hpp"
#include "aika/database/mysql_connection.hpp"
#include "aika/server/auth_listeners.hpp"
#include "aika/server/game_channels.hpp"

#include <winsock2.h>
#include <windows.h>

#include <atomic>
#include <array>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <string_view>
#include <thread>

namespace {

class TeeStreamBuffer final : public std::streambuf {
public:
    TeeStreamBuffer(std::streambuf* console, std::streambuf* file) noexcept
        : console_{console}, file_{file} {}

protected:
    int_type overflow(const int_type character) override {
        if (traits_type::eq_int_type(character, traits_type::eof())) {
            return traits_type::not_eof(character);
        }
        const auto value = traits_type::to_char_type(character);
        if (console_ != nullptr && traits_type::eq_int_type(
                console_->sputc(value), traits_type::eof())) {
            return traits_type::eof();
        }
        if (file_ != nullptr) {
            (void)file_->sputc(value);
        }
        return character;
    }

    std::streamsize xsputn(const char* data, const std::streamsize count) override {
        const auto console_written = console_ == nullptr ? 0 : console_->sputn(data, count);
        if (file_ != nullptr) {
            (void)file_->sputn(data, count);
        }
        return console_written;
    }

    int sync() override {
        if (file_ != nullptr) {
            (void)file_->pubsync();
        }
        return console_ == nullptr ? 0 : console_->pubsync();
    }

private:
    std::streambuf* console_{};
    std::streambuf* file_{};
};

class ServerLog final {
public:
    explicit ServerLog(const std::filesystem::path& path)
        : original_out_{std::cout.rdbuf()}, original_err_{std::clog.rdbuf()},
          original_cerr_{std::cerr.rdbuf()}, file_{path, std::ios::app},
          out_buffer_{original_out_, file_.is_open() ? file_.rdbuf() : nullptr},
          err_buffer_{original_err_, file_.is_open() ? file_.rdbuf() : nullptr} {
        std::cout.rdbuf(&out_buffer_);
        std::clog.rdbuf(&err_buffer_);
        std::cerr.rdbuf(&err_buffer_);
    }

    ~ServerLog() {
        std::cout.flush();
        std::clog.flush();
        std::cerr.flush();
        std::cout.rdbuf(original_out_);
        std::clog.rdbuf(original_err_);
        std::cerr.rdbuf(original_cerr_);
    }

    ServerLog(const ServerLog&) = delete;
    ServerLog& operator=(const ServerLog&) = delete;

private:
    std::streambuf* original_out_{};
    std::streambuf* original_err_{};
    std::streambuf* original_cerr_{};
    std::ofstream file_;
    TeeStreamBuffer out_buffer_;
    TeeStreamBuffer err_buffer_;
};

std::atomic_bool stop_requested{};

BOOL WINAPI handle_console_event(const DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT ||
        event == CTRL_CLOSE_EVENT || event == CTRL_LOGOFF_EVENT ||
        event == CTRL_SHUTDOWN_EVENT) {
        stop_requested.store(true);
        return TRUE;
    }
    return FALSE;
}

[[nodiscard]] bool is_server_root(const std::filesystem::path& root) noexcept {
    std::error_code error;
    if (!std::filesystem::is_regular_file(root / "AikaServer.ini", error) || error)
        return false;
    error.clear();
    if (!std::filesystem::is_regular_file(root / "SL.bin", error) || error)
        return false;
    error.clear();
    return std::filesystem::is_directory(root / "Data", error) && !error;
}

[[nodiscard]] std::filesystem::path discover_server_root() {
    std::filesystem::path executable_directory;
    std::array<wchar_t, 32768U> executable_path{};
    const auto path_length = GetModuleFileNameW(nullptr, executable_path.data(),
        static_cast<DWORD>(executable_path.size()));
    if (path_length > 0U && path_length < executable_path.size()) {
        executable_directory = std::filesystem::path{
            std::wstring_view{executable_path.data(), path_length}}.parent_path();
        auto directory = executable_directory;
        for (std::size_t depth = 0U; depth < 8U && !directory.empty(); ++depth) {
            if (is_server_root(directory)) return directory;

            const auto parent = directory.parent_path();
            if (parent == directory) break;
            directory = parent;
        }
    }

    // Runtime discovery deliberately does not fall back to the Delphi
    // checkout or the process working directory.
    return executable_directory.empty() ? std::filesystem::current_path()
                                        : executable_directory;
}

[[nodiscard]] std::filesystem::path server_root(const int argc, char** argv) {
    if (argc > 1) {
        return std::filesystem::path{argv[1]};
    }
#if defined(_MSC_VER)
    char* value = nullptr;
    std::size_t value_size{};
    if (_dupenv_s(&value, &value_size, "AIKA_SERVER_ROOT") == 0 &&
        value != nullptr && value_size > 1U) {
        const std::filesystem::path configured_root{value};
        std::free(value);
        return configured_root;
    }
    std::free(value);
#else
    if (const auto* value = std::getenv("AIKA_SERVER_ROOT");
        value != nullptr && *value != '\0') {
        return std::filesystem::path{value};
    }
#endif
    return discover_server_root();
}

} // namespace

int main(const int argc, char** argv) {
    std::cout << std::unitbuf;
    std::clog << std::unitbuf;
    std::cerr << std::unitbuf;
    try {
        const aika::config::RuntimeLayout layout{server_root(argc, argv)};
        ServerLog server_log{layout.root() / "AikaServer.log"};
        std::clog << "[boot] runtime root=" << layout.root().string() << std::endl;
        const auto config = aika::config::load_server_config(layout.config_file());
        std::clog << "[boot] server configuration loaded" << std::endl;
        const auto server_list = aika::data::load_server_list(layout.server_list_file());
        std::clog << "[boot] server list loaded entries=" << server_list.size() << std::endl;
        const auto tables = aika::data::GameTables::load(layout.data_directory());
        std::clog << "[boot] game tables loaded" << std::endl;
        const auto world_data = aika::data::load_world_data(
            layout.data_directory(), layout.npc_directory());
        std::clog << "[boot] world data loaded" << std::endl;
        aika::database::MysqlConnection database{config.mysql};
        std::clog << "[boot] database connected" << std::endl;
        const auto schema = database.inspect_schema();
        std::clog << "[boot] database schema inspected columns=" << schema.size() << std::endl;

        WSADATA winsock_data{};
        if (WSAStartup(MAKEWORD(2, 2), &winsock_data) != 0) {
            throw std::runtime_error{"Unable to initialize Winsock 2"};
        }

        std::cout << "Aika C++ bootstrap initialized.\n"
                  << "Server root: " << layout.root().string() << '\n'
                  << "Database connection: ready (utf8mb4).\n"
                  << "Database columns: " << schema.size() << '\n'
                  << "Server list entries: " << server_list.size() << '\n'
                  << "Items: " << tables.item_definitions.size()
                  << ", skills: " << tables.skill_definitions.size()
                  << ", premium items: " << tables.premium_items.size()
                  << ", recipes: " << tables.recipes.size() << '\n'
                  << "Experience levels: " << tables.experience_table.size()
                  << ", Pran levels: " << tables.pran_experience_table.size()
                  << ", quests (bytes): " << tables.quest_records.size()
                  << ", quest CSV: " << tables.quest_dialogue.size() << '\n'
                  << "Craft recipes: " << tables.make_items.size()
                  << ", ingredients: " << tables.make_item_ingredients.size()
                  << ", drop entries: " << tables.drop_entries.size() << '\n'
                  << "Mob templates: " << world_data.mob_templates.size()
                  << ", spawn points: " << world_data.mob_spawns.size()
                  << ", NPC definitions: " << world_data.npcs.size() << '\n'
                  << "Starting game channels (8822), login (8831), and token (8090) listeners.\n";

        auto login_grants = std::make_shared<aika::auth::LoginGrantRegistry>();
        aika::server::AuthListeners auth_listeners{config, server_list, login_grants};
        aika::server::GameChannels game_channels{
            config, server_list, tables, world_data, login_grants};
        auth_listeners.start();
        game_channels.start();
        SetConsoleCtrlHandler(handle_console_event, TRUE);
        std::cout << "Authentication listeners are running. Press Ctrl+C to stop.\n";
        while (!stop_requested.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
        }
        game_channels.stop();
        auth_listeners.stop();
        SetConsoleCtrlHandler(handle_console_event, FALSE);
        WSACleanup();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Aika C++ bootstrap failed: " << error.what() << '\n';
        return 1;
    }
}
