// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <vector>

int verify_stm32_image(const std::vector<unsigned char>& image);
int sign_stm32_image(std::vector<unsigned char>& image, const char* key_desc, const char* passphrase);
