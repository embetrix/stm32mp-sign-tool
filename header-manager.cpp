// SPDX-License-Identifier: GPL-3.0-or-later

#include "header-manager.hpp"

#include <cstring>
#include <stdexcept>
#include <string>

HeaderManager::HeaderManager(const std::vector<unsigned char>& image) {
    if (image.size() < sizeof(commonHeader)) {
        throw std::runtime_error("Image too short for an STM32 header");
    }
    std::memcpy(&commonHeader, image.data(), sizeof(commonHeader));
    if (std::strncmp(commonHeader.magic, STM32_MAGIC, sizeof(commonHeader.magic)) != 0) {
        throw std::runtime_error("Not an STM32 header (signature FAIL): expected magic '" +
                                 std::string(STM32_MAGIC) + "', got '" +
                                 std::string(commonHeader.magic, sizeof(commonHeader.magic)) + "'");
    }
}

int HeaderManager::getHeaderVersion() const {
    return (commonHeader.hdr_version >> 16) & 0xFF;
}

int HeaderManager::getHeaderMinorVersion() const {
    return (commonHeader.hdr_version >> 8) & 0xFF;
}
