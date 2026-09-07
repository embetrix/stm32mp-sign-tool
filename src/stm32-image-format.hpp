// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <optional>
#include <string>
#include <vector>

class STM32ImageFormat {
public:
    virtual ~STM32ImageFormat() = default;

    virtual int verify(const std::vector<unsigned char>& image) = 0;
    virtual int sign(std::vector<unsigned char>& image, const std::string& keyDesc, const std::optional<std::string>& passphrase) = 0;
};
