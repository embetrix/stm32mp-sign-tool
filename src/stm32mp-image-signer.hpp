// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "stm32-image-format-factory.hpp"

#include <memory>
#include <optional>
#include <string>
#include <vector>

class OpenSslKeys;
class Logger;

class STM32MPImageSigner {
public:
    STM32MPImageSigner(std::shared_ptr<OpenSslKeys> openSslKeys, std::shared_ptr<Logger> logger);

    int verifyImage(const std::vector<unsigned char>& image);
    int signImage(std::vector<unsigned char>& image, const std::string& keyDesc, const std::optional<std::string>& passphrase);

private:
    STM32ImageFormat* getImageFormat(int headerVersion, int headerMinorVersion);
    void printUnsupportedFormat(int headerVersion, int headerMinorVersion) const;

    std::shared_ptr<Logger> logger;
    STM32ImageFormatFactory imageFormatFactory;
    std::unique_ptr<STM32ImageFormat> imageFormat;
    int selectedHeaderVersion = -1;
    int selectedHeaderMinorVersion = -1;
};
