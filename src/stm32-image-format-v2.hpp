// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "stm32-image-format.hpp"

#include <memory>
#include <optional>
#include <string>
#include <vector>

class OpenSslKeys;
class Logger;

// Unsupported v2.0/v2.3 placeholder; v2.2 uses STM32ImageFormatV2_2.
class STM32ImageFormatV2 : public STM32ImageFormat {
public:
    STM32ImageFormatV2(std::shared_ptr<OpenSslKeys> openSslKeys, std::shared_ptr<Logger> logger, int headerMinorVersion);

    int verify(const std::vector<unsigned char>& image) override;
    int sign(std::vector<unsigned char>& image, const std::string& keyDesc, const std::optional<std::string>& passphrase) override;

private:
    int reportUnsupported() const;

    std::shared_ptr<OpenSslKeys> openSslKeys;
    std::shared_ptr<Logger> logger;
    int headerMinorVersion;
};
