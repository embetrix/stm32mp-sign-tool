// SPDX-License-Identifier: GPL-3.0-or-later

#include "stm32-image-format-v2-2.hpp"

#include "openssl-keys.hpp"

#include <array>
#include <cassert>
#include <cstring>
#include <iostream>
#include <openssl/sha.h>
#include <stdexcept>
#include <utility>

STM32ImageFormatV2_2::STM32ImageFormatV2_2(
    std::shared_ptr<OpenSslKeys> openSslKeys,
    std::shared_ptr<Logger> logger,
    std::vector<std::string> publicKeyDescriptors,
    int publicKeyIndex)
    : openSslKeys(std::move(openSslKeys)),
      logger(std::move(logger)),
      publicKeyDescriptors(std::move(publicKeyDescriptors)),
      publicKeyIndex(publicKeyIndex) {
    if (!this->openSslKeys) {
        throw std::invalid_argument("OpenSslKeys must not be null");
    }
    if (!this->logger) {
        throw std::invalid_argument("Logger must not be null");
    }
}

STM32ImageFormatV2_2::STM32HeaderV2_2
STM32ImageFormatV2_2::unpackHeader(const std::vector<unsigned char>& image) {
    assert(image.size() >= HEADER_SIZE);
    STM32HeaderV2_2 header{};
    size_t offset = 0;

    std::memcpy(&header.base_header, image.data() + offset, sizeof(header.base_header));
    offset += sizeof(header.base_header);

    if ((header.base_header.option_flags & (1U << 0U)) != 0) {
        STM32AuthenticationExtensionV2_2 authenticationExtension{};
        std::memcpy(&authenticationExtension,
                    image.data() + offset,
                    sizeof(authenticationExtension));
        header.authentication_extension = authenticationExtension;
        offset += sizeof(authenticationExtension);
    }

    if ((header.base_header.option_flags & (1U << 1U)) != 0) {
        STM32DecryptionExtensionV2_2 decryptionExtension{};
        std::memcpy(&decryptionExtension,
                    image.data() + offset,
                    sizeof(decryptionExtension));
        header.decryption_extension = decryptionExtension;
        offset += sizeof(decryptionExtension);
    }

    std::memcpy(&header.padding_extension.header,
                image.data() + offset,
                sizeof(header.padding_extension.header));

    return header;
}

void STM32ImageFormatV2_2::repackHeader(std::vector<unsigned char>& image,
                                        const STM32HeaderV2_2& header) {
    size_t offset = 0;

    STM32BaseHeaderV2_2 baseHeader = header.base_header;
    baseHeader.option_flags |= 1U << 31U;
    baseHeader.extensions_length = static_cast<uint32_t>(HEADER_SIZE - sizeof(baseHeader));
    std::memcpy(image.data() + offset, &baseHeader, sizeof(baseHeader));
    offset += sizeof(baseHeader);

    if (header.authentication_extension) {
        std::memcpy(image.data() + offset,
                    &header.authentication_extension.value(),
                    sizeof(header.authentication_extension.value()));
        offset += sizeof(header.authentication_extension.value());
    }

    if (header.decryption_extension) {
        std::memcpy(image.data() + offset,
                    &header.decryption_extension.value(),
                    sizeof(header.decryption_extension.value()));
        offset += sizeof(header.decryption_extension.value());
    }

    STM32PaddingExtensionHeaderV2_2 paddingHeader{};
    const unsigned char paddingExtensionType[4] = {'S', 'T', 0xff, 0xff};
    std::memcpy(&paddingHeader.extension_type,
                paddingExtensionType,
                sizeof(paddingExtensionType));
    paddingHeader.extension_length = static_cast<uint32_t>(HEADER_SIZE - offset);
    std::memcpy(image.data() + offset, &paddingHeader, sizeof(paddingHeader));
    offset += sizeof(paddingHeader);

    std::memset(image.data() + offset, 0, HEADER_SIZE - offset);
}

int STM32ImageFormatV2_2::verify(const std::vector<unsigned char>&) {
    throw std::runtime_error("STM32 header v2.2 verification is not implemented yet");
}

int STM32ImageFormatV2_2::sign(std::vector<unsigned char>&,
                               const std::string&,
                               const std::optional<std::string>&) {
    throw std::runtime_error("STM32 header v2.2 signing is not implemented yet");
}

int STM32ImageFormatV2_2::prepareAuthenticationExtension(STM32HeaderV2_2& header) {
    STM32AuthenticationExtensionV2_2 authenticationExtension{};

    const unsigned char extensionType[4] = {'S', 'T', 0x00, 0x02};
    std::memcpy(&authenticationExtension.extension_type,
                extensionType,
                sizeof(extensionType));
    authenticationExtension.extension_length =
        static_cast<uint32_t>(sizeof(authenticationExtension));
    authenticationExtension.public_key_index = static_cast<uint32_t>(publicKeyIndex);
    authenticationExtension.public_key_count = static_cast<uint32_t>(PUBLIC_KEY_COUNT);

    for (size_t index = 0; index < PUBLIC_KEY_COUNT; ++index) {
        EVP_PKEY* rawKey = nullptr;
        if (openSslKeys->loadPublicKey(publicKeyDescriptors[index], &rawKey) != 0) {
            std::cerr << "Failed to load public key: " << publicKeyDescriptors[index]
                      << std::endl;
            return -1;
        }
        EvpPkeyPtr key(rawKey);

        const std::vector<unsigned char> publicKey = openSslKeys->getRawPubkey(key.get());
        if (publicKey.size() != sizeof(authenticationExtension.ecdsa_public_key)) {
            std::cerr << "Invalid public key size: " << publicKeyDescriptors[index]
                      << std::endl;
            return -1;
        }

        const int keyAlgorithm = openSslKeys->getKeyAlgorithm(key.get());
        if (keyAlgorithm < 0) {
            return -1;
        }
        const uint32_t algorithm = static_cast<uint32_t>(keyAlgorithm);

        if (!OpenSslKeys::computePublicKeyHash(publicKey.data(), publicKey.size(), algorithm,
                                             authenticationExtension.public_key_hashes[index])) {
            std::cerr << "Failed to hash public key: " << publicKeyDescriptors[index]
                      << std::endl;
            return -1;
        }

        if (index == static_cast<size_t>(publicKeyIndex)) {
            authenticationExtension.ecdsa_algorithm = algorithm;
            std::memcpy(authenticationExtension.ecdsa_public_key,
                        publicKey.data(),
                        publicKey.size());
        }
    }

    if (OpenSslKeys::validatePublicKeyHashes(
            reinterpret_cast<const unsigned char*>(authenticationExtension.public_key_hashes),
            PUBLIC_KEY_COUNT) != 0) {
        return -1;
    }

    header.authentication_extension = authenticationExtension;
    header.base_header.option_flags |= 1U;
    return 0;
}
