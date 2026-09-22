// SPDX-License-Identifier: GPL-3.0-or-later

#include "stm32-image-format-factory.hpp"

#include "stm32-header-reader.hpp"
#include "openssl-keys.hpp"
#include "stm32-image-format-v1.hpp"
#include "stm32-image-format-v2.hpp"
#include "stm32-image-format-v2-2.hpp"
#include "logger.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <utility>

STM32ImageFormatFactory::STM32ImageFormatFactory(
    std::shared_ptr<OpenSslKeys> openSslKeys,
    std::shared_ptr<Logger> logger,
    std::vector<std::string> publicKeyDescriptors,
    int publicKeyIndex)
    : openSslKeys(std::move(openSslKeys)),
      logger(std::move(logger)),
      publicKeyDescriptors(std::move(publicKeyDescriptors)),
      publicKeyIndex(publicKeyIndex) {
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
                case STM32HeaderReader::STM32_HEADER_MINOR_V3:
                    return std::make_unique<STM32ImageFormatV2>(openSslKeys, logger, headerMinorVersion);
                case STM32HeaderReader::STM32_HEADER_MINOR_V2: {
                    if (publicKeyDescriptors.size()
                        != STM32ImageFormatV2_2::PUBLIC_KEY_COUNT) {
                        throw std::runtime_error(
                            "STM32 header v2.2 requires exactly eight public keys (-K)");
                    }
                    if (publicKeyIndex == -1) {
                        throw std::runtime_error(
                            "STM32 header v2.2 requires a public key index (-x)");
                    }
                    if (publicKeyIndex < 0
                        || publicKeyIndex
                               >= static_cast<int>(STM32ImageFormatV2_2::PUBLIC_KEY_COUNT)) {
                        throw std::runtime_error(
                            "STM32 header v2.2 public key index must be between 0 and 7");
                    }

                    std::array<std::string, STM32ImageFormatV2_2::PUBLIC_KEY_COUNT>
                        descriptors;
                    std::copy(publicKeyDescriptors.begin(),
                              publicKeyDescriptors.end(),
                              descriptors.begin());
                    return std::make_unique<STM32ImageFormatV2_2>(openSslKeys,
                                                                  logger,
                                                                  std::move(descriptors),
                                                                  static_cast<uint32_t>(
                                                                      publicKeyIndex));
                }
                default:
                    return nullptr;
            }
        case -1:
            return nullptr;
        default:
            return nullptr;
    }
}
