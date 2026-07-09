// SPDX-License-Identifier: GPL-3.0-or-later

#include "stm32_image_format.hpp"

#include "crypto_support.hpp"
#include "stm32_image_format_internal.hpp"

#include <cstring>
#include <iostream>

namespace {

// Validate the common header fields and return the header major version,
// or -1 if the image is too short or does not carry the STM32 magic.
int get_stm32_header_version(const std::vector<unsigned char>& image) {
    if (image.size() < sizeof(STM32HeaderCommon)) {
        std::cerr << "Image too short for an STM32 header: got " << image.size() << " bytes" << std::endl;
        return -1;
    }
    STM32HeaderCommon common;
    std::memcpy(&common, image.data(), sizeof(common));
    if (std::strncmp(common.magic, STM32_MAGIC, sizeof(common.magic)) != 0) {
        std::cerr << "Not an STM32 header (signature FAIL): expected magic '" << STM32_MAGIC
                  << "', got '" << std::string(common.magic, sizeof(common.magic)) << "'" << std::endl;
        return -1;
    }
    return (common.hdr_version >> 16) & 0xFF;
}

const STM32ImageFormat* get_stm32_image_format(int hdr_version) {
    switch (hdr_version) {
        case STM32_HEADER_V1:
            return get_stm32mp15_format();
        default:
            return nullptr;
    }
}

} // namespace

int verify_stm32_image(const std::vector<unsigned char>& image) {
    int hdr_version = get_stm32_header_version(image);
    const STM32ImageFormat* format = get_stm32_image_format(hdr_version);
    if (format) {
        return format->verify(image);
    }

    switch (hdr_version) {
        case STM32_HEADER_V2:
            std::cerr << "STM32 header v2 (STM32MP13x lines and STM32MP2 series) is not supported yet" << std::endl;
            return -1;
        case -1:
            return -1;
        default:
            std::cerr << "Unknown STM32 header version: " << hdr_version << std::endl;
            return -1;
    }
}

int sign_stm32_image(std::vector<unsigned char>& image, const char* key_desc, const char* passphrase) {
    if (image.empty()) {
        std::cerr << "Image data is empty" << std::endl;
        return -1;
    }
    if (!key_desc || std::strlen(key_desc) == 0) {
        std::cerr << "Key file path is empty" << std::endl;
        return -1;
    }
    int hdr_version = get_stm32_header_version(image);
    const STM32ImageFormat* format = get_stm32_image_format(hdr_version);
    if (format) {
        if (is_verbose_enabled()) {
            std::cout << format->description() << std::endl;
        }
        return format->sign(image, key_desc, passphrase);
    }

    switch (hdr_version) {
        case STM32_HEADER_V2:
            std::cerr << "STM32 header v2 (STM32MP13x lines and STM32MP2 series) is not supported yet" << std::endl;
            return -1;
        case -1:
            return -1;
        default:
            std::cerr << "Unknown STM32 header version: " << hdr_version << std::endl;
            return -1;
    }
}
