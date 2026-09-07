// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

class Logger {
public:
    bool isVerbose() const;
    void printHex(const std::string& label, const std::vector<unsigned char>& data) const;
    void setVerbose(bool enabled);

private:
    bool verbose = false;
};
