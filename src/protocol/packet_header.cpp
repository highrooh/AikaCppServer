#include "aika/protocol/packet_header.hpp"

namespace aika::protocol {
namespace {

[[nodiscard]] constexpr std::uint16_t read_u16_le(
    const std::span<const std::byte> bytes,
    const std::size_t offset) noexcept {
    const auto low = std::to_integer<std::uint8_t>(bytes[offset]);
    const auto high = std::to_integer<std::uint8_t>(bytes[offset + 1]);
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(low) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(high) << 8U));
}

[[nodiscard]] constexpr std::uint32_t read_u32_le(
    const std::span<const std::byte> bytes,
    const std::size_t offset) noexcept {
    const auto b0 = std::to_integer<std::uint8_t>(bytes[offset]);
    const auto b1 = std::to_integer<std::uint8_t>(bytes[offset + 1]);
    const auto b2 = std::to_integer<std::uint8_t>(bytes[offset + 2]);
    const auto b3 = std::to_integer<std::uint8_t>(bytes[offset + 3]);
    return static_cast<std::uint32_t>(b0) |
           (static_cast<std::uint32_t>(b1) << 8U) |
           (static_cast<std::uint32_t>(b2) << 16U) |
           (static_cast<std::uint32_t>(b3) << 24U);
}

constexpr void write_u16_le(
    const std::uint16_t value,
    const std::span<std::byte> bytes,
    const std::size_t offset) noexcept {
    bytes[offset] = static_cast<std::byte>(value & 0xFFU);
    bytes[offset + 1] = static_cast<std::byte>((value >> 8U) & 0xFFU);
}

constexpr void write_u32_le(
    const std::uint32_t value,
    const std::span<std::byte> bytes,
    const std::size_t offset) noexcept {
    bytes[offset] = static_cast<std::byte>(value & 0xFFU);
    bytes[offset + 1] = static_cast<std::byte>((value >> 8U) & 0xFFU);
    bytes[offset + 2] = static_cast<std::byte>((value >> 16U) & 0xFFU);
    bytes[offset + 3] = static_cast<std::byte>((value >> 24U) & 0xFFU);
}

} // namespace

HeaderDecodeResult decode_header(const std::span<const std::byte> bytes) noexcept {
    if (bytes.size() < PacketHeader::wire_size) {
        return {{}, HeaderDecodeError::insufficient_bytes};
    }

    PacketHeader header{};
    header.size = read_u16_le(bytes, 0);
    header.transport_byte_2 = std::to_integer<std::uint8_t>(bytes[2]);
    header.transport_byte_3 = std::to_integer<std::uint8_t>(bytes[3]);
    header.client_index = read_u16_le(bytes, 4);
    header.opcode = read_u16_le(bytes, 6);
    header.timestamp = read_u32_le(bytes, 8);

    if (header.size < PacketHeader::minimum_packet_size) {
        return {header, HeaderDecodeError::invalid_packet_size};
    }

    return {header, HeaderDecodeError::none};
}

std::array<std::byte, PacketHeader::wire_size>
encode_header(const PacketHeader& header) noexcept {
    std::array<std::byte, PacketHeader::wire_size> bytes{};
    const auto view = std::span<std::byte>{bytes};

    write_u16_le(header.size, view, 0);
    bytes[2] = static_cast<std::byte>(header.transport_byte_2);
    bytes[3] = static_cast<std::byte>(header.transport_byte_3);
    write_u16_le(header.client_index, view, 4);
    write_u16_le(header.opcode, view, 6);
    write_u32_le(header.timestamp, view, 8);
    return bytes;
}

} // namespace aika::protocol
