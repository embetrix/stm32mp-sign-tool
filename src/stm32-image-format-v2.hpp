// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "stm32-image-format.hpp"

#include <memory>
#include <optional>
#include <string>
#include <vector>

class OpenSslKeys;
class Logger;

// Header v2 (512 bytes): STM32MP13x lines and the STM32MP2 series.
//
// The format is recognised and dispatched to, but nothing is implemented yet:
// sign() and verify() report the unsupported line and fail. What is missing is
// the v2 layout itself and the extension headers it carries, so an image with
// a v2 header is still rejected rather than signed incorrectly.
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
