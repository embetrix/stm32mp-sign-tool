// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <vector>

class STM32ImageFormat {
public:
    virtual ~STM32ImageFormat() = default;

    virtual int verify(const std::vector<unsigned char>& image) = 0;
    virtual int sign(std::vector<unsigned char>& image, const std::string& keyDesc, const std::optional<std::string>& passphrase) = 0;

protected:
    static int alignPayload(std::vector<unsigned char>& image, size_t headerSize, uint32_t& length) {
        if (image.size() < headerSize || length > image.size() - headerSize) {
            std::cerr << "Image too short: expected at least "
                      << static_cast<uint64_t>(headerSize) + length << " bytes, got "
                      << image.size() << std::endl;
            return -1;
        }
        // ST tool rounds payload to multiples of 32 bytes and appends 0's to fill that requirement
        constexpr uint32_t alignment = 32;
        const uint32_t padding = (alignment - length % alignment) % alignment;
        if (padding > std::numeric_limits<uint32_t>::max() - length) {
            std::cerr << "Aligned payload length exceeds the STM32 header limit" << std::endl;
            return -1;
        }
        image.insert(image.begin() + static_cast<std::ptrdiff_t>(headerSize + length), padding, 0);
        length += padding;
        return 0;
    }
};
