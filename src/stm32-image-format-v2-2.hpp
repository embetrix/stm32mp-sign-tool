// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "stm32-image-format.hpp"
#include "openssl-keys.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

class Logger;

class STM32ImageFormatV2_2 : public STM32ImageFormat {
public:
    static constexpr std::size_t PUBLIC_KEY_COUNT = OpenSslKeys::PUBLIC_KEY_COUNT;
    static constexpr std::size_t HEADER_SIZE = 512;
    static constexpr std::size_t SIGNATURE_SIZE = 64;

    STM32ImageFormatV2_2(std::shared_ptr<OpenSslKeys> openSslKeys,
                         std::shared_ptr<Logger> logger,
                         std::vector<std::string> publicKeyDescriptors = {},
                         int publicKeyIndex = -1);

    int verify(const std::vector<unsigned char>& image) override;
    int sign(std::vector<unsigned char>& image,
             const std::string& keyDesc,
             const std::optional<std::string>& passphrase) override;

private:
    // Layout:
    // [128-byte base header]
    // [optional authentication extension]
    // [optional decryption extension]
    // [padding extension to complete the 512-byte header]
    // [image payload]
    struct STM32BaseHeaderV2_2 {
        char magic[4];
        unsigned char signature[SIGNATURE_SIZE];
        uint32_t checksum;
        uint32_t hdr_version;
        uint32_t length;
        uint32_t entry_addr;
        uint32_t reserved[3];
        uint32_t rollback_version;
        uint32_t option_flags;
        uint32_t extensions_length;
        uint32_t binary_type;
        unsigned char padding[16];
    } __attribute__((packed));

    struct STM32AuthenticationExtensionV2_2 {
        uint32_t extension_type;
        uint32_t extension_length;
        uint32_t public_key_index;
        uint32_t public_key_count;
        uint32_t ecdsa_algorithm;
        unsigned char ecdsa_public_key[OpenSslKeys::PUBLIC_KEY_SIZE];
        unsigned char public_key_hashes[PUBLIC_KEY_COUNT][SHA256_DIGEST_LENGTH];
    } __attribute__((packed));

    struct STM32DecryptionExtensionV2_2 {
        uint32_t extension_type;
        uint32_t extension_length;
        uint32_t key_size;
        uint32_t derivation_constant;
        unsigned char plaintext_hash[16];
    } __attribute__((packed));

    struct STM32PaddingExtensionHeaderV2_2 {
        uint32_t extension_type;
        uint32_t extension_length;
        // Variable-length zero padding follows this fixed prefix.
    } __attribute__((packed));

    struct STM32PaddingExtensionV2_2 {
        STM32PaddingExtensionHeaderV2_2 header;
    };

    // Logical representation of the complete header. Unlike the packed
    // structures above, this type does not represent one contiguous wire
    // structure because the extensions are optional and padding is variable.
    struct STM32HeaderV2_2 {
        STM32BaseHeaderV2_2 base_header;
        std::optional<STM32AuthenticationExtensionV2_2> authentication_extension;
        std::optional<STM32DecryptionExtensionV2_2> decryption_extension;
        STM32PaddingExtensionV2_2 padding_extension;
    };

    STM32HeaderV2_2 unpackHeader(const std::vector<unsigned char>& image);
    void repackHeader(std::vector<unsigned char>& image, const STM32HeaderV2_2& header);
    int prepareAuthenticationExtension(STM32HeaderV2_2& header);

    std::shared_ptr<OpenSslKeys> openSslKeys;
    std::shared_ptr<Logger> logger;
    std::vector<std::string> publicKeyDescriptors;
    int publicKeyIndex;
};
