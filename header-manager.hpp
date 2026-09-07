// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <vector>

class HeaderManager {
public:
    enum STM32HeaderVersion {
        STM32_HEADER_V1 = 1,
        STM32_HEADER_V2 = 2,
    };

    enum STM32HeaderVersionMinor {
        STM32_HEADER_MINOR_V0 = 0,
        STM32_HEADER_MINOR_V2 = 2,
        STM32_HEADER_MINOR_V3 = 3,
    };

    explicit HeaderManager(const std::vector<unsigned char>& image);

    int getHeaderVersion() const;
    int getHeaderMinorVersion() const;

private:
    static constexpr const char* STM32_MAGIC = "STM2";

    struct STM32HeaderCommon {
        char magic[4];
        unsigned char signature[64];
        uint32_t checksum;
        uint32_t hdr_version;
        uint32_t length;
        uint32_t entry_addr;
        uint32_t reserved1;
        uint32_t load_addr;
        uint32_t reserved2;
        uint32_t rollback_version;
    } __attribute__((packed));

    STM32HeaderCommon commonHeader;
};
