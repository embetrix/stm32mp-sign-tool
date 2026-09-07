// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "stm32-image-format.hpp"

#include <memory>

class OpenSSLSupport;
class Utils;

class STM32ImageFormatFactory {
public:
    STM32ImageFormatFactory(std::shared_ptr<OpenSSLSupport> openSslSupport, std::shared_ptr<Utils> utils);

    std::unique_ptr<STM32ImageFormat> getFormat(int headerVersion, int headerMinorVersion) const;

private:
    std::shared_ptr<OpenSSLSupport> openSslSupport;
    std::shared_ptr<Utils> utils;
};
