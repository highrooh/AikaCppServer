#include "aika/network/tcp_listener.hpp"

#include <ws2tcpip.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <unordered_set>
#include <utility>

namespace aika::network {

struct TcpListener::State final {
    SOCKET listener{INVALID_SOCKET};
    std::atomic_bool stopping{};
    std::string bind_address;
    std::uint16_t port{};
    std::size_t max_clients{};
    ClientHandler handler;
    std::mutex clients_mutex;
    std::condition_variable clients_changed;
    std::unordered_set<SOCKET> clients;
};

namespace {

void serve_client(const std::shared_ptr<TcpListener::State>& state, const SOCKET client) noexcept {
    try {
        state->handler(client);
    } catch (...) {
        // Do not log packet contents, account names, tokens, or HTTP bodies.
    }
    std::lock_guard lock{state->clients_mutex};
    shutdown(client, SD_BOTH);
    closesocket(client);
    state->clients.erase(client);
    state->clients_changed.notify_all();
}

void accept_clients(const std::shared_ptr<TcpListener::State>& state) noexcept {
    while (!state->stopping.load()) {
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(state->listener, &read_set);
        timeval timeout{0, 250000};
        const auto ready = select(0, &read_set, nullptr, nullptr, &timeout);
        if (ready == SOCKET_ERROR) {
            if (!state->stopping.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds{25});
            }
            continue;
        }
        if (ready == 0 || !FD_ISSET(state->listener, &read_set)) {
            continue;
        }

        const SOCKET client = accept(state->listener, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            continue;
        }
        sockaddr_in peer{};
        int peer_size = static_cast<int>(sizeof(peer));
        char peer_address[INET_ADDRSTRLEN]{};
        if (getpeername(client, reinterpret_cast<sockaddr*>(&peer), &peer_size) == 0 &&
            InetNtopA(AF_INET, &peer.sin_addr, peer_address,
                static_cast<DWORD>(sizeof(peer_address))) != nullptr) {
            std::clog << "[tcp] accepted remote=" << peer_address << ':'
                      << ntohs(peer.sin_port) << " listener=" << state->bind_address
                      << ':' << state->port << std::endl;
        } else {
            std::clog << "[tcp] accepted listener=" << state->bind_address
                      << ':' << state->port << std::endl;
        }
        {
            std::lock_guard lock{state->clients_mutex};
            if (state->stopping.load() || state->clients.size() >= state->max_clients) {
                shutdown(client, SD_BOTH);
                closesocket(client);
                continue;
            }
            state->clients.insert(client);
        }
        try {
            std::thread{serve_client, state, client}.detach();
        } catch (...) {
            std::lock_guard lock{state->clients_mutex};
            shutdown(client, SD_BOTH);
            closesocket(client);
            state->clients.erase(client);
            state->clients_changed.notify_all();
        }
    }
}

} // namespace

TcpListener::TcpListener() = default;

TcpListener::~TcpListener() {
    stop();
}

void TcpListener::start(const std::string& bind_address, const std::uint16_t port,
        const std::size_t max_clients, ClientHandler handler) {
    if (state_ != nullptr || max_clients == 0U || !handler) {
        throw std::logic_error{"Invalid TCP listener start state"};
    }

    auto state = std::make_shared<State>();
    state->max_clients = max_clients;
    state->bind_address = bind_address;
    state->port = port;
    state->handler = std::move(handler);
    state->listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (state->listener == INVALID_SOCKET) {
        throw std::runtime_error{"Unable to create TCP listener socket"};
    }

    BOOL reuse_address = TRUE;
    setsockopt(state->listener, SOL_SOCKET, SO_REUSEADDR,
        reinterpret_cast<const char*>(&reuse_address), sizeof(reuse_address));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (InetPtonA(AF_INET, bind_address.c_str(), &address.sin_addr) != 1) {
        closesocket(state->listener);
        throw std::runtime_error{"Invalid IPv4 bind address for TCP listener"};
    }
    if (bind(state->listener, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR ||
        listen(state->listener, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(state->listener);
        throw std::runtime_error{"Unable to bind or listen on the requested TCP port"};
    }

    state_ = std::move(state);
    try {
        accept_thread_ = std::thread{accept_clients, state_};
    } catch (...) {
        closesocket(state_->listener);
        state_.reset();
        throw;
    }
}

void TcpListener::stop() noexcept {
    auto state = std::move(state_);
    if (state == nullptr) {
        return;
    }
    state->stopping.store(true);
    shutdown(state->listener, SD_BOTH);
    closesocket(state->listener);
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }

    std::unique_lock lock{state->clients_mutex};
    for (const auto client : state->clients) {
        shutdown(client, SD_BOTH);
    }
    state->clients_changed.wait(lock, [&state] { return state->clients.empty(); });
}

bool TcpListener::running() const noexcept {
    return state_ != nullptr && !state_->stopping.load();
}

} // namespace aika::network
