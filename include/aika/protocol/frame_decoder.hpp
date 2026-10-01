#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace aika::protocol {

enum class FrameStatus : std::uint8_t {
    accepted,
    frame_ready,
    need_more_data,
    invalid_size,
    buffer_limit_exceeded,
};

struct FrameResult final {
    FrameStatus status{FrameStatus::need_more_data};
    std::vector<std::byte> bytes;
};

// Accumulates TCP bytes and yields complete Aika frames. The two-byte length
// prefix is available before decryption; each returned frame is still encrypted.
class FrameDecoder final {
public:
    static constexpr std::size_t protocol_max_frame_size = 65535U;
    static constexpr std::size_t default_buffer_limit = protocol_max_frame_size * 4U;

    explicit FrameDecoder(
        std::size_t max_frame_size = protocol_max_frame_size,
        std::size_t max_buffered_bytes = default_buffer_limit);

    [[nodiscard]] FrameStatus feed(std::span<const std::byte> bytes);
    [[nodiscard]] FrameResult next_frame();
    void reset() noexcept;

    [[nodiscard]] std::size_t buffered_bytes() const noexcept;
    [[nodiscard]] FrameStatus failure() const noexcept;

private:
    void compact();
    [[nodiscard]] FrameStatus fail(FrameStatus status) noexcept;

    std::vector<std::byte> buffer_;
    std::size_t read_offset_{};
    std::size_t max_frame_size_{};
    std::size_t max_buffered_bytes_{};
    FrameStatus failure_{FrameStatus::accepted};
};

} // namespace aika::protocol
