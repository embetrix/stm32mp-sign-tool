// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "stm32-image-format.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class OpenSslKeys;
class Logger;

class STM32ImageFormatFactory {
public:
    STM32ImageFormatFactory(std::shared_ptr<OpenSslKeys> openSslKeys,
                            std::shared_ptr<Logger> logger,
                            std::vector<std::string> publicKeyDescriptors,
                            int publicKeyIndex);

    std::unique_ptr<STM32ImageFormat> getFormat(int headerVersion, int headerMinorVersion) const;

private:
    std::shared_ptr<OpenSslKeys> openSslKeys;
    std::shared_ptr<Logger> logger;
    std::vector<std::string> publicKeyDescriptors;
    int publicKeyIndex;
};
