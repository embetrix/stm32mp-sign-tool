// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "stm32-image-format.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class OpenSSLSupport;
class Utils;

class STM32ImageFormatMP15 : public STM32ImageFormat {
public:
    STM32ImageFormatMP15(std::shared_ptr<OpenSSLSupport> openSslSupport, std::shared_ptr<Utils> utils);

    int verify(const std::vector<unsigned char>& image) override;
    int sign(std::vector<unsigned char>& image, const std::string& keyDesc, const std::string& passphrase) override;

private:
    struct STM32HeaderV1 {
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
        uint32_t option_flags;
        uint32_t ecdsa_algo;
        unsigned char ecdsa_pubkey[64];
        unsigned char padding[83];
        unsigned char binary_type;
    } __attribute__((packed));

    STM32HeaderV1 unpackHeader(const std::vector<unsigned char>& image);
    void repackHeader(std::vector<unsigned char>& image, const STM32HeaderV1& header);

    std::shared_ptr<OpenSSLSupport> openSslSupport;
    std::shared_ptr<Utils> utils;
};
