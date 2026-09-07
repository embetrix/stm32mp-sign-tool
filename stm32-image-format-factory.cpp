// SPDX-License-Identifier: GPL-3.0-or-later

#include "stm32-image-format-factory.hpp"

#include "header-manager.hpp"
#include "openssl-support.hpp"
#include "stm32-image-format-mp15.hpp"
#include "utils.hpp"

#include <stdexcept>
#include <utility>

STM32ImageFormatFactory::STM32ImageFormatFactory(std::shared_ptr<OpenSSLSupport> openSslSupport, std::shared_ptr<Utils> utils)
    : openSslSupport(std::move(openSslSupport)),
      utils(std::move(utils)) {
    if (!this->openSslSupport) {
        throw std::invalid_argument("OpenSSLSupport must not be null");
    }
    if (!this->utils) {
        throw std::invalid_argument("Utils must not be null");
    }
}

std::unique_ptr<STM32ImageFormat> STM32ImageFormatFactory::getFormat(int headerVersion, int headerMinorVersion) const {
    switch (headerVersion) {
        case HeaderManager::STM32_HEADER_V1:
            return std::make_unique<STM32ImageFormatMP15>(openSslSupport, utils);
        case HeaderManager::STM32_HEADER_V2:
            switch (headerMinorVersion) {
                case HeaderManager::STM32_HEADER_MINOR_V0:
                case HeaderManager::STM32_HEADER_MINOR_V2:
                case HeaderManager::STM32_HEADER_MINOR_V3:
                default:
                    return nullptr;
            }
        case -1:
            return nullptr;
        default:
            return nullptr;
    }
}
