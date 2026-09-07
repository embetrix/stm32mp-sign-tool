// SPDX-License-Identifier: GPL-3.0-or-later

#include "stm32-image-format-factory.hpp"

#include "stm32-header-reader.hpp"
#include "openssl-keys.hpp"
#include "stm32-image-format-v1.hpp"
#include "stm32-image-format-v2.hpp"
#include "logger.hpp"

#include <stdexcept>
#include <utility>

STM32ImageFormatFactory::STM32ImageFormatFactory(std::shared_ptr<OpenSslKeys> openSslKeys, std::shared_ptr<Logger> logger)
    : openSslKeys(std::move(openSslKeys)),
      logger(std::move(logger)) {
    if (!this->openSslKeys) {
        throw std::invalid_argument("OpenSslKeys must not be null");
    }
    if (!this->logger) {
        throw std::invalid_argument("Logger must not be null");
    }
}

std::unique_ptr<STM32ImageFormat> STM32ImageFormatFactory::getFormat(int headerVersion, int headerMinorVersion) const {
    switch (headerVersion) {
        case STM32HeaderReader::STM32_HEADER_V1:
            return std::make_unique<STM32ImageFormatV1>(openSslKeys, logger);
        case STM32HeaderReader::STM32_HEADER_V2:
            switch (headerMinorVersion) {
                case STM32HeaderReader::STM32_HEADER_MINOR_V0:
                case STM32HeaderReader::STM32_HEADER_MINOR_V2:
                case STM32HeaderReader::STM32_HEADER_MINOR_V3:
                    return std::make_unique<STM32ImageFormatV2>(openSslKeys, logger, headerMinorVersion);
                default:
                    return nullptr;
            }
        case -1:
            return nullptr;
        default:
            return nullptr;
    }
}
