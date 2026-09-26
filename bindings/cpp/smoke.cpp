// SPDX-License-Identifier: MPL-2.0
#include "opencrate_ffi.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

static void require(int32_t code, const char* operation) {
    if (code != OCB_OK) {
        throw std::runtime_error(std::string(operation) + " failed with status " + std::to_string(code));
    }
}

int main() {
    if (ocb_abi_version() != 1) {
        throw std::runtime_error("unsupported Open Crate FFI ABI");
    }
    std::array<uint8_t, OCB_KEY_LEN> secret{};
    std::array<uint8_t, OCB_KEY_LEN> public_key{};
    require(ocb_generate_recipient(secret.data(), public_key.data()), "generate");

    constexpr std::string_view purpose = "example.cpp.v1";
    constexpr std::string_view context = "object-7";
    constexpr std::string_view plaintext = "arbitrary bytes from C++";
    std::vector<uint8_t> envelope(plaintext.size() + OCB_ENVELOPE_OVERHEAD);
    size_t envelope_len = 0;
    require(ocb_seal(public_key.data(), reinterpret_cast<const uint8_t*>(purpose.data()), purpose.size(),
                     reinterpret_cast<const uint8_t*>(context.data()), context.size(),
                     reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
                     envelope.data(), envelope.size(), &envelope_len), "seal");
    envelope.resize(envelope_len);

    std::vector<uint8_t> opened(plaintext.size());
    size_t opened_len = 0;
    require(ocb_open(secret.data(), reinterpret_cast<const uint8_t*>(purpose.data()), purpose.size(),
                     reinterpret_cast<const uint8_t*>(context.data()), context.size(),
                     envelope.data(), envelope.size(), opened.data(), opened.size(), &opened_len), "open");
    if (opened_len != plaintext.size() ||
        std::string_view(reinterpret_cast<const char*>(opened.data()), opened_len) != plaintext) {
        throw std::runtime_error("round trip mismatch");
    }
    constexpr std::string_view wrong_context = "object-8";
    const auto bad = ocb_open(secret.data(), reinterpret_cast<const uint8_t*>(purpose.data()), purpose.size(),
                              reinterpret_cast<const uint8_t*>(wrong_context.data()), wrong_context.size(),
                              envelope.data(), envelope.size(), opened.data(), opened.size(), &opened_len);
    if (bad != OCB_CRYPTO) {
        throw std::runtime_error("changed context was accepted");
    }
    std::cout << "C++ round trip and context rejection passed\n";
    // This example's secret is ephemeral. Applications must use protected
    // storage and a reliable secure erase for persistent recipient secrets.
}
