// SPDX-License-Identifier: GPL-3.0-or-later

#include "stm32-image-format-v2-2.hpp"

#include <cstring>
#include <stdexcept>
#include <utility>

STM32ImageFormatV2_2::STM32ImageFormatV2_2(
    std::shared_ptr<OpenSslKeys> openSslKeys,
    std::shared_ptr<Logger> logger,
    std::array<std::string, PUBLIC_KEY_COUNT> publicKeyDescriptors,
    uint32_t publicKeyIndex)
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
    if (this->publicKeyIndex >= PUBLIC_KEY_COUNT) {
        throw std::invalid_argument("Public key index must be between 0 and 7");
    }
}

STM32ImageFormatV2_2::STM32HeaderV2_2
STM32ImageFormatV2_2::unpackHeader(const std::vector<unsigned char>& image) {
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

void STM32ImageFormatV2_2::repackHeader(std::vector<unsigned char>&,
                                        const STM32HeaderV2_2&) {
    throw std::runtime_error("STM32 header v2.2 repacking is not implemented yet");
}

int STM32ImageFormatV2_2::verify(const std::vector<unsigned char>&) {
    throw std::runtime_error("STM32 header v2.2 verification is not implemented yet");
}

int STM32ImageFormatV2_2::sign(std::vector<unsigned char>&,
                               const std::string&,
                               const std::optional<std::string>&) {
    throw std::runtime_error("STM32 header v2.2 signing is not implemented yet");
}

int STM32ImageFormatV2_2::prepareAuthenticationExtension(
    std::vector<unsigned char>&,
    const std::string&,
    const std::optional<std::string>&) {
    throw std::runtime_error("STM32 header v2.2 authentication extension preparation is not implemented yet");
}
