#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace aika::protocol {

enum class CryptoError : std::uint8_t {
    none,
    insufficient_bytes,
    invalid_packet_size,
    checksum_mismatch,
};

struct CryptoResult final {
    CryptoError error{CryptoError::none};

    [[nodiscard]] constexpr explicit operator bool() const noexcept {
        return error == CryptoError::none;
    }
};

// Ports the active Delphi Encrypt(pointer, size) path. The caller supplies
// the random key and GetTickCount-style timestamp so output is reproducible.
[[nodiscard]] CryptoResult encrypt_frame(
    std::span<std::byte> frame,
    std::uint8_t random_key,
    std::uint32_t timestamp_ms) noexcept;

// Decrypts one complete encrypted frame whose total size is stored at bytes 0-1.
// A checksum mismatch is reported after the frame has been transformed in place,
// matching the Delphi routine's mutation-before-check behavior.
[[nodiscard]] CryptoResult decrypt_frame(std::span<std::byte> frame) noexcept;

} // namespace aika::protocol
