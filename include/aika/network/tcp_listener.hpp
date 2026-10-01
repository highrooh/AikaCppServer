#pragma once

#include <winsock2.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>

namespace aika::network {

class TcpListener final {
public:
    using ClientHandler = std::function<void(SOCKET)>;
    struct State;

    TcpListener();
    ~TcpListener();
    TcpListener(const TcpListener&) = delete;
    TcpListener& operator=(const TcpListener&) = delete;

    void start(const std::string& bind_address, std::uint16_t port,
               std::size_t max_clients, ClientHandler handler);
    void stop() noexcept;
    [[nodiscard]] bool running() const noexcept;

private:
    std::shared_ptr<State> state_;
    std::thread accept_thread_;
};

} // namespace aika::network
