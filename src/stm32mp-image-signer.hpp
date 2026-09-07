// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "stm32-image-format-factory.hpp"

#include <memory>
#include <string>
#include <vector>

class OpenSSLSupport;
class Utils;

class STM32MPImageSigner {
public:
    STM32MPImageSigner(std::shared_ptr<OpenSSLSupport> openSslSupport, std::shared_ptr<Utils> utils);

    int verifyImage(const std::vector<unsigned char>& image);
    int signImage(std::vector<unsigned char>& image, const std::string& keyDesc, const std::string& passphrase);

private:
    STM32ImageFormat* getImageFormat(int headerVersion, int headerMinorVersion);
    void printUnsupportedFormat(int headerVersion, int headerMinorVersion) const;

    std::shared_ptr<Utils> utils;
    STM32ImageFormatFactory imageFormatFactory;
    std::unique_ptr<STM32ImageFormat> imageFormat;
    int selectedHeaderVersion = -1;
    int selectedHeaderMinorVersion = -1;
};
