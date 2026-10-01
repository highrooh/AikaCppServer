#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace aika::protocol {

struct PacketHeader final {
    static constexpr std::size_t wire_size = 12;
    static constexpr std::uint16_t minimum_packet_size =
        static_cast<std::uint16_t>(wire_size);

    // The Delphi packed record is Size, Key, ChkSum, Index, Code, Time.
    // During transport encryption Key and ChkSum are used as crypto metadata,
    // so keep those two bytes opaque until the exact crypto stage is known.
    std::uint16_t size{};
    std::uint8_t transport_byte_2{};
    std::uint8_t transport_byte_3{};
    std::uint16_t client_index{};
    std::uint16_t opcode{};
    std::uint32_t timestamp{};
};

enum class HeaderDecodeError : std::uint8_t {
    none,
    insufficient_bytes,
    invalid_packet_size,
};

struct HeaderDecodeResult final {
    PacketHeader header{};
    HeaderDecodeError error{HeaderDecodeError::none};

    [[nodiscard]] constexpr explicit operator bool() const noexcept {
        return error == HeaderDecodeError::none;
    }
};

// Decodes the 12-byte Delphi TPacketHeader wire layout explicitly as
// little-endian fields. `bytes` may contain only the header or a full frame.
[[nodiscard]] HeaderDecodeResult decode_header(std::span<const std::byte> bytes) noexcept;

// Serializes a header into the exact 12-byte wire layout. Packet size must
// include the header, matching the Delphi SendPacket(Packet, Header.Size).
[[nodiscard]] std::array<std::byte, PacketHeader::wire_size>
encode_header(const PacketHeader& header) noexcept;

} // namespace aika::protocol
