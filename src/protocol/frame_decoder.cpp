#include "aika/protocol/frame_decoder.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace aika::protocol {
namespace {

[[nodiscard]] constexpr std::uint16_t read_size_prefix(
    const std::span<const std::byte> bytes) noexcept {
    const auto low = std::to_integer<std::uint8_t>(bytes[0]);
    const auto high = std::to_integer<std::uint8_t>(bytes[1]);
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(low) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(high) << 8U));
}

} // namespace

FrameDecoder::FrameDecoder(
    const std::size_t max_frame_size,
    const std::size_t max_buffered_bytes)
    : max_frame_size_{max_frame_size}, max_buffered_bytes_{max_buffered_bytes} {
    if (max_frame_size_ < 12U || max_frame_size_ > protocol_max_frame_size) {
        throw std::invalid_argument{"Aika maximum frame size must be between 12 and 65535 bytes"};
    }
    if (max_buffered_bytes_ < max_frame_size_) {
        throw std::invalid_argument{"Aika receive buffer limit cannot be smaller than the maximum frame"};
    }
}

FrameStatus FrameDecoder::feed(const std::span<const std::byte> bytes) {
    if (failure_ != FrameStatus::accepted) {
        return failure_;
    }

    if (read_offset_ != 0U &&
        (read_offset_ > buffer_.size() / 2U ||
         buffer_.size() - read_offset_ + bytes.size() > max_buffered_bytes_)) {
        compact();
    }

    const auto unread = buffer_.size() - read_offset_;
    if (bytes.size() > max_buffered_bytes_ - unread) {
        return fail(FrameStatus::buffer_limit_exceeded);
    }
    buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
    return FrameStatus::accepted;
}

FrameResult FrameDecoder::next_frame() {
    if (failure_ != FrameStatus::accepted) {
        return {failure_, {}};
    }

    const auto unread = buffer_.size() - read_offset_;
    if (unread < 2U) {
        return {FrameStatus::need_more_data, {}};
    }

    const auto remaining = std::span<const std::byte>{buffer_}.subspan(read_offset_);
    const auto declared_size = static_cast<std::size_t>(read_size_prefix(remaining));
    if (declared_size < 12U || declared_size > max_frame_size_) {
        return {fail(FrameStatus::invalid_size), {}};
    }
    if (unread < declared_size) {
        return {FrameStatus::need_more_data, {}};
    }

    std::vector<std::byte> frame(
        remaining.begin(), remaining.begin() + static_cast<std::ptrdiff_t>(declared_size));
    read_offset_ += declared_size;
    if (read_offset_ == buffer_.size()) {
        buffer_.clear();
        read_offset_ = 0U;
    }
    return {FrameStatus::frame_ready, std::move(frame)};
}

void FrameDecoder::reset() noexcept {
    buffer_.clear();
    read_offset_ = 0U;
    failure_ = FrameStatus::accepted;
}

std::size_t FrameDecoder::buffered_bytes() const noexcept {
    return buffer_.size() - read_offset_;
}

FrameStatus FrameDecoder::failure() const noexcept {
    return failure_;
}

void FrameDecoder::compact() {
    if (read_offset_ == 0U) {
        return;
    }
    const auto unread = buffer_.size() - read_offset_;
    std::move(buffer_.begin() + static_cast<std::ptrdiff_t>(read_offset_),
              buffer_.end(), buffer_.begin());
    buffer_.resize(unread);
    read_offset_ = 0U;
}

FrameStatus FrameDecoder::fail(const FrameStatus status) noexcept {
    failure_ = status;
    return failure_;
}

} // namespace aika::protocol
