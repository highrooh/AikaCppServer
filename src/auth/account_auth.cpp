#include "aika/auth/account_auth.hpp"

#include "aika/database/mysql_connection.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace aika::auth {
namespace {

[[nodiscard]] std::string create_token() {
    std::array<unsigned char, 16> random_bytes{};
    const auto status = BCryptGenRandom(nullptr, random_bytes.data(),
        static_cast<ULONG>(random_bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0) {
        throw std::runtime_error{"Windows cryptographic random generation failed"};
    }
    std::ostringstream token;
    token << std::hex << std::setfill('0');
    for (const auto value : random_bytes) {
        token << std::setw(2) << static_cast<unsigned>(value);
    }
    return token.str();
}

[[nodiscard]] std::int64_t unix_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

[[nodiscard]] std::string md5_hex(const std::string& value) {
    if (value.size() > (std::numeric_limits<ULONG>::max)()) {
        return {};
    }

    BCRYPT_ALG_HANDLE algorithm{};
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_MD5_ALGORITHM, nullptr, 0U) < 0) {
        return {};
    }

    DWORD object_length{};
    DWORD hash_length{};
    DWORD bytes_written{};
    BCRYPT_HASH_HANDLE hash_handle{};
    std::string result;
    std::vector<UCHAR> hash_object;
    std::array<UCHAR, 16> digest{};

    const auto object_status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length), &bytes_written, 0U);
    const auto hash_status = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hash_length), sizeof(hash_length), &bytes_written, 0U);
    if (object_status >= 0 && hash_status >= 0 && hash_length == digest.size()) {
        hash_object.resize(object_length);
        if (BCryptCreateHash(algorithm, &hash_handle, hash_object.data(), object_length,
                nullptr, 0U, 0U) >= 0 &&
            BCryptHashData(hash_handle,
                reinterpret_cast<PUCHAR>(const_cast<char*>(value.data())),
                static_cast<ULONG>(value.size()), 0U) >= 0 &&
            BCryptFinishHash(hash_handle, digest.data(),
                static_cast<ULONG>(digest.size()), 0U) >= 0) {
            constexpr char digits[] = "0123456789abcdef";
            result.reserve(digest.size() * 2U);
            for (const auto byte : digest) {
                result.push_back(digits[byte >> 4U]);
                result.push_back(digits[byte & 0x0FU]);
            }
        }
    }

    if (hash_handle != nullptr) {
        BCryptDestroyHash(hash_handle);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0U);
    return result;
}

} // namespace

AccountAuthService::AccountAuthService(config::DatabaseConfig database_config)
    : database_config_{std::move(database_config)} {}

std::string AccountAuthService::issue_token(
    const std::string& username, const std::string& password,
    const bool allow_loopback_plaintext) const {
    aika::database::MysqlConnection database{database_config_};
    const auto account = database.find_account(username);
    if (!account.has_value()) {
        return "0";
    }
    if (account->password_hash != password &&
        (!allow_loopback_plaintext || md5_hex(password) != account->password_hash)) {
        return "-1";
    }

    if (account->account_status == 2U) {
        return "-2";
    }
    if (account->account_status == 8U) {
        const auto now = unix_now();
        const auto ban_expires = account->last_token_creation_time +
            static_cast<std::int64_t>(account->ban_days) * 86400;
        if (account->ban_days > 0U && ban_expires <= now) {
            database.clear_expired_ban(username);
            return "-22";
        }
        return "-8";
    }
    if (account->account_status == 10U) {
        return "-10";
    }

    const auto token = create_token();
    database.save_account_token(username, token, unix_now(), account->premium_time);
    return token;
}

std::string AccountAuthService::character_count(
        const std::string& username, const std::string& token) const {
    aika::database::MysqlConnection database{database_config_};
    const auto account = database.find_account(username);
    if (!account.has_value()) {
        return "0";
    }
    if (account->last_token != token) {
        return "-1";
    }
    const auto count = database.count_characters(account->id);
    return "CNT " + std::to_string(count) + " 0 0 0<br>" +
        std::to_string(account->nation) + " 0 0 0";
}

std::string AccountAuthService::renew_token(
        const std::string& username, const std::string& token) const {
    aika::database::MysqlConnection database{database_config_};
    const auto account = database.find_account(username);
    if (!account.has_value()) {
        return "0";
    }
    if (account->last_token != token) {
        return "-1";
    }
    database.save_account_token(username, token, unix_now(), account->premium_time);
    return token;
}

void LoginGrantRegistry::authorize(std::string username,
        const std::uint32_t account_id, std::string peer_address) {
    std::transform(username.begin(), username.end(), username.begin(),
        [](const unsigned char ch) {
            return static_cast<char>(ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch);
        });
    std::lock_guard lock{mutex_};
    grants_[std::move(username)] = Grant{
        account_id, std::move(peer_address),
        std::chrono::steady_clock::now() + std::chrono::seconds{30}};
}

bool LoginGrantRegistry::consume(const std::string& username,
        const std::uint32_t account_id, const std::string& peer_address) {
    auto normalized_username = username;
    std::transform(normalized_username.begin(), normalized_username.end(),
        normalized_username.begin(), [](const unsigned char ch) {
            return static_cast<char>(ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch);
        });
    std::lock_guard lock{mutex_};
    const auto found = grants_.find(normalized_username);
    if (found == grants_.end()) return false;
    if (found->second.expires_at <= std::chrono::steady_clock::now()) {
        grants_.erase(found);
        return false;
    }
    if (found->second.account_id != account_id ||
        found->second.peer_address != peer_address) return false;
    grants_.erase(found);
    return true;
}

} // namespace aika::auth
