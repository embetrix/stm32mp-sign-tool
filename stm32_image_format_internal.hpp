// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <vector>

constexpr char STM32_MAGIC[] = "STM2"; // 0x53544D32

// Fields common to all STM32 header versions (offsets 0x00-0x63)
struct STM32HeaderCommon {
    char magic[4];
    unsigned char signature[64];
    uint32_t checksum;
    uint32_t hdr_version; // byte 1: minor, byte 2: major
    uint32_t length;
    uint32_t entry_addr;
    uint32_t reserved1; // Set to 0
    uint32_t load_addr;
    uint32_t reserved2; // Set to 0
    uint32_t rollback_version;
} __attribute__((packed));

enum STM32HeaderVersion {
    STM32_HEADER_V1 = 1, // STM32MP15x lines
    STM32_HEADER_V2 = 2, // STM32MP13x lines and STM32MP2 series
};

class STM32ImageFormat {
public:
    virtual ~STM32ImageFormat() = default;

    virtual const char* description() const = 0;
    virtual int sign(std::vector<unsigned char>& image, const char* key_desc, const char* passphrase) const = 0;
    virtual int verify(const std::vector<unsigned char>& image) const = 0;
};

const STM32ImageFormat* get_stm32mp15_format();
