// SPDX-License-Identifier: GPL-3.0-or-later
#include "logger.hpp"
#include "openssl-keys.hpp"
#include "stm32mp-image-signer.hpp"

#include <fstream>
#include <iterator>
#include <memory>
#include <vector>

// Test helper for verifyImage(), which has no standalone CLI option.
int main(int argc, char* argv[]) {
    if (argc != 2) {
        return 2;
    }
    std::ifstream input(argv[1], std::ios::binary);
    if (!input) {
        return 2;
    }
    const std::vector<unsigned char> image((std::istreambuf_iterator<char>(input)), {});
    STM32MPImageSigner signer(std::make_shared<OpenSslKeys>(),
                              std::make_shared<Logger>());
    return signer.verifyImage(image) == 0 ? 0 : 1;
}
