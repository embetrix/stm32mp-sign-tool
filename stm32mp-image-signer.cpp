// SPDX-License-Identifier: GPL-3.0-or-later

#include "stm32mp-image-signer.hpp"

#include "header-manager.hpp"
#include "utils.hpp"

#include <iostream>
#include <stdexcept>
#include <utility>

STM32MPImageSigner::STM32MPImageSigner(std::shared_ptr<OpenSSLSupport> openSslSupport, std::shared_ptr<Utils> utils)
    : utils(utils),
      imageFormatFactory(std::move(openSslSupport), std::move(utils)) {
}

STM32ImageFormat* STM32MPImageSigner::getImageFormat(int headerVersion, int headerMinorVersion) {
    if (!imageFormat ||
        selectedHeaderVersion != headerVersion ||
        selectedHeaderMinorVersion != headerMinorVersion) {
        imageFormat = imageFormatFactory.getFormat(headerVersion, headerMinorVersion);
        selectedHeaderVersion = headerVersion;
        selectedHeaderMinorVersion = headerMinorVersion;
    }

    return imageFormat.get();
}

void STM32MPImageSigner::printUnsupportedFormat(int headerVersion, int headerMinorVersion) const {
    switch (headerVersion) {
        case HeaderManager::STM32_HEADER_V2:
            switch (headerMinorVersion) {
                case HeaderManager::STM32_HEADER_MINOR_V0:
                    std::cerr << "STM32 header v2.0 (STM32MP13x lines) is not supported yet" << std::endl;
                    return;
                case HeaderManager::STM32_HEADER_MINOR_V2:
                    std::cerr << "STM32 header v2.2 (STM32MP23x lines and STM32MP25x lines) is not supported yet" << std::endl;
                    return;
                case HeaderManager::STM32_HEADER_MINOR_V3:
                    std::cerr << "STM32 header v2.3 (STM32MP21x lines) is not supported yet" << std::endl;
                    return;
                case -1:
                    std::cerr << "STM32 header v2 (STM32MP13x lines and STM32MP2 series) is not supported yet" << std::endl;
                    return;
                default:
                    std::cerr << "Unknown STM32 header v2 minor version: " << headerMinorVersion << std::endl;
                    return;
            }
        case -1:
            return;
        default:
            std::cerr << "Unknown STM32 header version: " << headerVersion << std::endl;
            return;
    }
}

int STM32MPImageSigner::verifyImage(const std::vector<unsigned char>& image) {
    try {
        HeaderManager headerManager(image);
        int headerVersion = headerManager.getHeaderVersion();
        STM32ImageFormat* format = getImageFormat(headerVersion, -1);
        if (!format) {
            printUnsupportedFormat(headerVersion, -1);
            return -1;
        }
        return format->verify(image);
    } catch (const std::runtime_error& error) {
        std::cerr << error.what() << std::endl;
        return -1;
    }
}

int STM32MPImageSigner::signImage(std::vector<unsigned char>& image, const std::string& keyDesc, const std::string& passphrase) {
    if (image.empty()) {
        std::cerr << "Image data is empty" << std::endl;
        return -1;
    }
    if (keyDesc.empty()) {
        std::cerr << "Key file path is empty" << std::endl;
        return -1;
    }
    try {
        HeaderManager headerManager(image);
        int headerVersion = headerManager.getHeaderVersion();
        int headerMinorVersion = -1;
        if (headerVersion == HeaderManager::STM32_HEADER_V2) {
            headerMinorVersion = headerManager.getHeaderMinorVersion();
        }
        STM32ImageFormat* format = getImageFormat(headerVersion, headerMinorVersion);
        if (!format) {
            printUnsupportedFormat(headerVersion, headerMinorVersion);
            return -1;
        }
        if (headerVersion == HeaderManager::STM32_HEADER_V1 && utils->isVerbose()) {
            std::cout << "STM32 header v1 (STM32MP15x lines)" << std::endl;
        }
        return format->sign(image, keyDesc, passphrase);
    } catch (const std::runtime_error& error) {
        std::cerr << error.what() << std::endl;
        return -1;
    }
}
