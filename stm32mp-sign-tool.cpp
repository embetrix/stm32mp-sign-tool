// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * (C) Copyright 2024
 * Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 3 of
 * the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <getopt.h>
#include <openssl/crypto.h>

#include "crypto_support.hpp"
#include "stm32_image_format.hpp"

namespace {

void usage(const char* argv0) {
    std::cout << "Usage: " << argv0 << " -k key_desc [-p passphrase/pin] [-m module_path] [-v] [-i input_file] [-o output_file] [-h hash_file]" << std::endl;
}

} // namespace

int main(int argc, char* argv[]) {
    const char* key_desc = nullptr;
    const char* passphrase = nullptr;
    const char* input_file = nullptr;
    const char* output_file = nullptr;
    const char* output_hash = nullptr;

    int opt;
    if (argc == 1) {
        usage(argv[0]);
        return -1;
    }

    while ((opt = getopt(argc, argv, "k:p:h:vi:o:m:")) != -1) {
        switch (opt) {
            case 'k':
                key_desc = optarg;
                break;
            case 'p':
                passphrase = optarg;
                break;
            case 'v':
                set_verbose(true);
                break;
            case 'h':
                output_hash = optarg;
                break;
            case 'i':
                input_file = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'm':
                set_pkcs11_module(optarg);
                break;
            default:
                usage(argv[0]);
                return -1;
        }
    }

    if (!key_desc) {
        std::cerr << "Must specify a key file or pkcs11 uri" << std::endl;
        return -1;
    }

    if (input_file) {
        std::ifstream image_file(input_file, std::ios::binary);
        std::vector<unsigned char> image((std::istreambuf_iterator<char>(image_file)), std::istreambuf_iterator<char>());
        image_file.close();

        if (sign_stm32_image(image, key_desc, passphrase) != 0) {
            return -1;
        }

        if (output_file) {
            std::ofstream output(output_file, std::ios::binary);
            output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
            output.close();
        }
    }

    if (output_hash) {
        if (hash_pubkey(key_desc, passphrase, output_hash) != 0) {
            return -1;
        }
    }

    cleanup_crypto_providers();

    // Securely erase the passphrase
    if (passphrase) {
        OPENSSL_cleanse(static_cast<void*>(const_cast<char*>(passphrase)), std::strlen(passphrase));
    }

    // Securely erase the key_desc in case it's a pkcs11 uri with pin
    if (key_desc) {
        OPENSSL_cleanse(static_cast<void*>(const_cast<char*>(key_desc)), std::strlen(key_desc));
    }

    return 0;
}
