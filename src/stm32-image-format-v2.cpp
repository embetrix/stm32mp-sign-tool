// SPDX-License-Identifier: GPL-3.0-or-later

#include "stm32-image-format-v2.hpp"

#include "stm32-header-reader.hpp"

#include <iostream>
#include <utility>

STM32ImageFormatV2::STM32ImageFormatV2(std::shared_ptr<OpenSslKeys> openSslKeys, std::shared_ptr<Logger> logger, int headerMinorVersion)
    : openSslKeys(std::move(openSslKeys)),
      logger(std::move(logger)),
      headerMinorVersion(headerMinorVersion) {
}

int STM32ImageFormatV2::reportUnsupported() const {
    switch (headerMinorVersion) {
        case STM32HeaderReader::STM32_HEADER_MINOR_V0:
            std::cerr << "STM32 header v2.0 (STM32MP13x lines) is not supported yet" << std::endl;
            break;
        case STM32HeaderReader::STM32_HEADER_MINOR_V2:
            std::cerr << "STM32 header v2.2 (STM32MP23x lines and STM32MP25x lines) is not supported yet" << std::endl;
            break;
        case STM32HeaderReader::STM32_HEADER_MINOR_V3:
            std::cerr << "STM32 header v2.3 (STM32MP21x lines) is not supported yet" << std::endl;
            break;
        default:
            std::cerr << "STM32 header v2 (STM32MP13x lines and STM32MP2 series) is not supported yet" << std::endl;
            break;
    }
    return -1;
}

int STM32ImageFormatV2::verify(const std::vector<unsigned char>&) {
    return reportUnsupported();
}

int STM32ImageFormatV2::sign(std::vector<unsigned char>&, const std::string&, const std::optional<std::string>&) {
    return reportUnsupported();
}
