#include "aika/server/auth_listeners.hpp"

#include "aika/auth/account_auth.hpp"
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
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace aika::server {
namespace {

constexpr std::size_t max_http_bytes = 16384U;
constexpr std::uint16_t login_opcode = 0x81U;
constexpr std::uint16_t login_response_opcode = 0x82U;

[[nodiscard]] bool is_loopback_peer(const SOCKET socket) noexcept {
    sockaddr_storage peer{};
    int peer_size = static_cast<int>(sizeof(peer));
    if (getpeername(socket, reinterpret_cast<sockaddr*>(&peer), &peer_size) == SOCKET_ERROR) {
        return false;
    }
    if (peer.ss_family == AF_INET) {
        const auto* address = reinterpret_cast<const sockaddr_in*>(&peer);
        return (ntohl(address->sin_addr.s_addr) >> 24U) == 127U;
    }
    if (peer.ss_family == AF_INET6) {
        const auto* address = reinterpret_cast<const sockaddr_in6*>(&peer);
        return IN6_IS_ADDR_LOOPBACK(&address->sin6_addr) != 0;
    }
    return false;
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

[[nodiscard]] bool receive_bytes(const SOCKET socket, std::vector<std::byte>& bytes,
        std::size_t* received_size = nullptr) {
    std::array<char, 4096> buffer{};
    const auto received = recv(socket, buffer.data(), static_cast<int>(buffer.size()), 0);
    if (received <= 0) {
        return false;
    }
    if (received_size != nullptr) {
        *received_size = static_cast<std::size_t>(received);
    }
    const auto* first = reinterpret_cast<const std::byte*>(buffer.data());
    bytes.insert(bytes.end(), first, first + received);
    return true;
}

[[nodiscard]] std::string fixed_string(
    const std::span<const std::byte> bytes, const std::size_t offset,
    const std::size_t field_size) {
    if (offset > bytes.size() || field_size > bytes.size() - offset) {
        return {};
    }
    std::string value;
    value.reserve(field_size);
    for (std::size_t i = 0U; i < field_size; ++i) {
        const auto ch = std::to_integer<unsigned char>(bytes[offset + i]);
        if (ch == 0U) {
            break;
        }
        value.push_back(static_cast<char>(ch));
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.pop_back();
    }
    auto first = value.begin();
    while (first != value.end() && (*first == ' ' || *first == '\t')) {
        ++first;
    }
    value.erase(value.begin(), first);
    std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char ch) {
        return static_cast<char>(ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch);
    });
    return value;
}

void write_u32_le(const std::uint32_t value, const std::span<std::byte> bytes,
        const std::size_t offset) noexcept {
    for (std::size_t i = 0U; i < 4U; ++i) {
        bytes[offset + i] = static_cast<std::byte>((value >> (i * 8U)) & 0xFFU);
    }
}

[[nodiscard]] bool send_all(const SOCKET socket, const std::span<const std::byte> bytes) {
    std::size_t sent_total = 0U;
    while (sent_total < bytes.size()) {
        const auto sent = send(socket,
            reinterpret_cast<const char*>(bytes.data() + sent_total),
            static_cast<int>(bytes.size() - sent_total), 0);
        if (sent <= 0) {
            return false;
        }
        sent_total += static_cast<std::size_t>(sent);
    }
    return true;
}

[[nodiscard]] std::uint8_t random_transport_key() {
    std::uint8_t key{};
    const auto status = BCryptGenRandom(nullptr, &key, sizeof(key),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0) {
        throw std::runtime_error{"Windows cryptographic random generation failed"};
    }
    return static_cast<std::uint8_t>(key % 255U);
}

[[nodiscard]] bool process_login_frame(
    const SOCKET socket, std::vector<std::byte>& frame,
    const config::DatabaseConfig& database_config,
    auth::LoginGrantRegistry& login_grants) {
    const auto connection_id = static_cast<unsigned long long>(socket);
    const auto reject = [connection_id](const char* reason) {
        std::clog << "[login-tcp] rejected connection=" << connection_id
                  << " reason=" << reason << std::endl;
        return false;
    };
    const auto decrypt_result = protocol::decrypt_frame(frame);
    (void)decrypt_result; // The Delphi login path dispatches even on checksum mismatch.

    const auto decoded = protocol::decode_header(frame);
    if (!decoded) {
        return reject("invalid packet header");
    }
    if (decoded.header.opcode != login_opcode) {
        std::clog << "[login-tcp] ignored connection=" << connection_id
                  << " opcode=0x" << std::hex << decoded.header.opcode << std::dec
                  << " bytes=" << frame.size() << std::endl;
        return true;
    }
    if (frame.size() < 76U) {
        return reject("packet shorter than expected");
    }

    auto username = fixed_string(frame, 12U, 32U);
    auto token = fixed_string(frame, 44U, 32U);
    if (token.empty() && frame.size() >= 108U) {
        token = fixed_string(frame, 76U, 32U);
    }
    if (username.empty() || token.empty()) {
        return reject("login fields missing");
    }

    database::MysqlConnection database{database_config};
    const auto account = database.find_account(username);
    if (!account.has_value() || account->account_status == 8U) {
        return reject(account.has_value() ? "account banned" : "account not found");
    }
    auto saved_token = account->last_token;
    std::transform(saved_token.begin(), saved_token.end(), saved_token.begin(),
        [](const unsigned char ch) {
            return static_cast<char>(ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch);
        });
    const auto age = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() -
        account->last_token_creation_time;
    if (token != saved_token || age >= 300) {
        return reject(token != saved_token ? "token mismatch" : "token expired");
    }

    constexpr std::size_t response_size = 25U;
    std::array<std::byte, response_size> response{};
    protocol::PacketHeader header{};
    header.size = static_cast<std::uint16_t>(response_size);
    header.opcode = login_response_opcode;
    const auto encoded_header = protocol::encode_header(header);
    std::copy(encoded_header.begin(), encoded_header.end(), response.begin());
    write_u32_le(account->id, response, 12U);
    write_u32_le(static_cast<std::uint32_t>(GetTickCount()), response, 16U);
    response[20] = static_cast<std::byte>(account->nation & 0xFFU);

    const auto encrypted = protocol::encrypt_frame(response, random_transport_key(),
        static_cast<std::uint32_t>(GetTickCount()));
    if (!encrypted || !send_all(socket, response)) {
        return reject("response send failed");
    }
    login_grants.authorize(username, account->id, peer_ipv4_address(socket));
    std::clog << "[login-tcp] accepted connection=" << connection_id << std::endl;
    return true;
}

void serve_login_client(const SOCKET socket,
        const config::DatabaseConfig& database_config,
        auth::LoginGrantRegistry& login_grants) {
    DWORD timeout_ms = 15000U;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));

    protocol::FrameDecoder decoder;
    std::vector<std::byte> incoming;
    std::vector<std::byte> first_packet_prefix;
    bool first_packet = true;
    std::size_t total_received = 0U;
    while (true) {
        std::size_t received_size{};
        if (!receive_bytes(socket, incoming, &received_size)) {
            std::clog << "[login-tcp] connection closed="
                      << static_cast<unsigned long long>(socket)
                      << " bytes=" << total_received
                      << " buffered=" << (first_packet
                          ? first_packet_prefix.size() : decoder.buffered_bytes())
                      << std::endl;
            return;
        }
        total_received += received_size;
        std::clog << "[login-tcp] received connection="
                  << static_cast<unsigned long long>(socket)
                  << " bytes=" << received_size
                  << " total=" << total_received << std::endl;
        if (first_packet) {
            first_packet_prefix.insert(first_packet_prefix.end(),
                incoming.begin(), incoming.end());
            incoming.clear();
            if (first_packet_prefix.size() < 6U) {
                std::clog << "[login-tcp] waiting for initial header connection="
                          << static_cast<unsigned long long>(socket)
                          << " buffered=" << first_packet_prefix.size() << std::endl;
                continue;
            }
            // LoginSocket.pas removes four bytes whenever this recv contains
            // more than 1116 bytes. Its ReceiveData method passes the remainder
            // to PacketControl, which decrypts the fixed 4096-byte buffer.
            // Match that legacy rule instead of trying to infer the prefix from
            // two encrypted length fields.
            const bool removed_legacy_prefix = first_packet_prefix.size() > 1116U;
            if (removed_legacy_prefix) {
                first_packet_prefix.erase(first_packet_prefix.begin(),
                    first_packet_prefix.begin() + 4);
            }
            const auto declared_size = static_cast<std::size_t>(
                std::to_integer<std::uint8_t>(first_packet_prefix[0]) |
                (static_cast<std::uint16_t>(
                    std::to_integer<std::uint8_t>(first_packet_prefix[1])) << 8U));
            std::clog << "[login-tcp] initial framing connection="
                      << static_cast<unsigned long long>(socket)
                      << " removed_legacy_prefix=" << (removed_legacy_prefix ? "yes" : "no")
                      << " declared_bytes=" << declared_size
                      << " received_bytes=" << first_packet_prefix.size() << std::endl;
            incoming.swap(first_packet_prefix);
            first_packet = false;
        }
        const auto fed = decoder.feed(incoming);
        incoming.clear();
        if (fed != protocol::FrameStatus::accepted) {
            std::clog << "[login-tcp] invalid frame connection="
                      << static_cast<unsigned long long>(socket) << std::endl;
            return;
        }
        while (true) {
            auto result = decoder.next_frame();
            if (result.status == protocol::FrameStatus::need_more_data) {
                break;
            }
            if (result.status != protocol::FrameStatus::frame_ready) {
                std::clog << "[login-tcp] incomplete frame connection="
                          << static_cast<unsigned long long>(socket) << std::endl;
                return;
            }
            const auto header = protocol::decode_header(result.bytes);
            if (header) {
                std::clog << "[login-tcp] packet connection="
                          << static_cast<unsigned long long>(socket)
                          << " opcode=0x" << std::hex << header.header.opcode << std::dec
                          << " bytes=" << result.bytes.size() << std::endl;
            } else {
                std::clog << "[login-tcp] packet with invalid header connection="
                          << static_cast<unsigned long long>(socket) << std::endl;
            }
            if (!process_login_frame(socket, result.bytes, database_config, login_grants)) {
                return;
            }
        }
    }
}

[[nodiscard]] int hex_digit(const char value) noexcept {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

[[nodiscard]] std::string form_decode(const std::string_view value) {
    std::string decoded;
    decoded.reserve(value.size());
    for (std::size_t i = 0U; i < value.size(); ++i) {
        if (value[i] == '+') {
            decoded.push_back(' ');
        } else if (value[i] == '%' && i + 2U < value.size()) {
            const auto high = hex_digit(value[i + 1U]);
            const auto low = hex_digit(value[i + 2U]);
            if (high < 0 || low < 0) {
                throw std::runtime_error{"Malformed URL-encoded form field"};
            }
            decoded.push_back(static_cast<char>((high << 4) | low));
            i += 2U;
        } else {
            decoded.push_back(value[i]);
        }
    }
    return decoded;
}

[[nodiscard]] std::map<std::string, std::string, std::less<>> parse_form(
        const std::string_view body) {
    std::map<std::string, std::string, std::less<>> parameters;
    std::size_t offset = 0U;
    while (offset <= body.size()) {
        const auto end = body.find('&', offset);
        const auto field = body.substr(offset,
            end == std::string_view::npos ? body.size() - offset : end - offset);
        const auto equal = field.find('=');
        const auto key = form_decode(field.substr(0U, equal));
        const auto value = equal == std::string_view::npos
            ? std::string{} : form_decode(field.substr(equal + 1U));
        parameters[key] = value;
        if (end == std::string_view::npos) {
            break;
        }
        offset = end + 1U;
    }
    return parameters;
}

[[nodiscard]] std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](const unsigned char ch) {
            return static_cast<char>(ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch);
        });
    return value;
}

[[nodiscard]] std::string handle_http_request(
        const SOCKET socket, const auth::AccountAuthService& auth_service,
        const std::string_view server_players_response) {
    DWORD timeout_ms = 10000U;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    std::string request;
    std::array<char, 4096> buffer{};
    std::size_t header_end = std::string::npos;
    std::size_t content_length = 0U;
    std::string method;
    std::string path;
    while (header_end == std::string::npos ||
           request.size() < header_end + 4U + content_length) {
        const auto received = recv(socket, buffer.data(), static_cast<int>(buffer.size()), 0);
        if (received <= 0 || request.size() + static_cast<std::size_t>(received) > max_http_bytes) {
            return "0";
        }
        request.append(buffer.data(), static_cast<std::size_t>(received));
        if (header_end == std::string::npos) {
            header_end = request.find("\r\n\r\n");
            if (header_end == std::string::npos) {
                continue;
            }
            const auto line_end = request.find("\r\n");
            if (line_end == std::string::npos || line_end > header_end) {
                return "0";
            }
            const auto first_space = request.find(' ');
            const auto second_space = request.find(' ', first_space + 1U);
            if (first_space == std::string::npos || second_space == std::string::npos ||
                second_space > line_end) {
                return "0";
            }
            method = request.substr(0U, first_space);
            path = request.substr(first_space + 1U, second_space - first_space - 1U);
            std::size_t line = line_end + 2U;
            while (line < header_end) {
                const auto end = request.find("\r\n", line);
                if (end == std::string::npos || end > header_end) break;
                const auto colon = request.find(':', line);
                if (colon != std::string::npos && colon < end &&
                    lower_ascii(request.substr(line, colon - line)) == "content-length") {
                    const auto value_start = request.find_first_not_of(" \t", colon + 1U);
                    if (value_start == std::string::npos || value_start >= end) return "0";
                    const auto parsed = std::from_chars(request.data() + value_start,
                        request.data() + end, content_length, 10);
                    if (parsed.ec != std::errc{} || parsed.ptr != request.data() + end ||
                        content_length > max_http_bytes) return "0";
                }
                line = end + 2U;
            }
        }
    }

    const auto query = path.find('?');
    if (query != std::string::npos) {
        path.resize(query);
    }
    if (path == "/servers/serv00.asp") {
        std::clog << "[http-auth] route=serv00 method=" << method
                  << " response_bytes=" << server_players_response.size() << std::endl;
        return std::string{server_players_response};
    }
    if (method != "POST") {
        return "NGNIX iNiz Games \xC2\xA9 2023 - 503 Forbidden";
    }
    if (path != "/member/aika_get_token.asp" &&
        path != "/servers/aika_get_chrcnt.asp" &&
        path != "/servers/aika_reset_flag.asp") {
        return {};
    }
    const auto params = parse_form(std::string_view{request}.substr(header_end + 4U,
        content_length));
    const auto username = params.find("id");
    const auto password = params.find("pw");
    if (username == params.end() || password == params.end()) {
        return "0";
    }
    if (path == "/member/aika_get_token.asp") {
        auto response = auth_service.issue_token(username->second, password->second,
            is_loopback_peer(socket));
        std::clog << "[http-auth] route=issue-token response_bytes="
                  << response.size() << std::endl;
        return response;
    }
    if (path == "/servers/aika_get_chrcnt.asp") {
        auto response = auth_service.character_count(username->second, password->second);
        std::clog << "[http-auth] route=character-count response_bytes="
                  << response.size() << std::endl;
        return response;
    }
    if (path == "/servers/aika_reset_flag.asp") {
        auto response = auth_service.renew_token(username->second, password->second);
        std::clog << "[http-auth] route=renew-token response_bytes="
                  << response.size() << std::endl;
        return response;
    }
    return {};
}

void serve_http_client(const SOCKET socket, const auth::AccountAuthService& auth_service,
        const std::string& server_players_response) {
    std::string body;
    try {
        body = handle_http_request(socket, auth_service, server_players_response);
    } catch (...) {
        body = "0";
    }
    const std::string response = std::string{"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"} +
        "Content-Length: " + std::to_string(body.size()) +
        "\r\nConnection: close\r\n\r\n" + body;
    (void)send_all(socket, std::as_bytes(std::span{response.data(), response.size()}));
}

} // namespace

AuthListeners::AuthListeners(config::ServerConfig config,
        std::vector<data::ServerEntry> servers,
        std::shared_ptr<auth::LoginGrantRegistry> login_grants)
    : config_{std::move(config)}, servers_{std::move(servers)},
      login_grants_{std::move(login_grants)} {
    if (login_grants_ == nullptr)
        throw std::invalid_argument{"Login grant registry is required"};
    std::unordered_set<std::string> active_addresses;
    const auto channel_count = std::min<std::size_t>(config_.channels, servers_.size());
    for (std::size_t i = 0U; i < servers_.size(); ++i) {
        if (i < channel_count && !servers_[i].ip.empty() &&
            active_addresses.insert(servers_[i].ip).second) {
            server_players_response_ += "1 ";
        } else {
            server_players_response_ += "-1 ";
        }
    }
    if (!server_players_response_.empty()) {
        server_players_response_.pop_back();
    }
}

AuthListeners::~AuthListeners() {
    stop();
}

void AuthListeners::start() {
    const auto database_config = config_.mysql;
    const auto login_grants = login_grants_;
    login_listener_.start("0.0.0.0", 8831U, 200U,
        [database_config, login_grants](const SOCKET socket) {
            serve_login_client(socket, database_config, *login_grants);
        });
    try {
        auto auth_service = auth::AccountAuthService{database_config};
        const auto server_players_response = server_players_response_;
        token_listener_.start("0.0.0.0", 8090U, 128U,
            [auth_service = std::move(auth_service), server_players_response](const SOCKET socket) {
                serve_http_client(socket, auth_service, server_players_response);
            });
    } catch (...) {
        login_listener_.stop();
        throw;
    }
}

void AuthListeners::stop() noexcept {
    token_listener_.stop();
    login_listener_.stop();
}

} // namespace aika::server
