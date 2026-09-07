// SPDX-License-Identifier: GPL-3.0-or-later

#include "utils.hpp"

#include <iomanip>
#include <iostream>

void Utils::setVerbose(bool enabled) {
    verbose = enabled;
}

bool Utils::isVerbose() const {
    return verbose;
}

void Utils::printHex(const std::string& label, const std::vector<unsigned char>& data) const {
    if (!verbose)
        return;
    std::cout << label << ": ";
    for (unsigned char byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
}
