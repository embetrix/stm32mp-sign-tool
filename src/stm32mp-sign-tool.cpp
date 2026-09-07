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
#include <getopt.h>
#include <memory>
#include <string>
#include <vector>
#include <stdexcept>
#include <openssl/crypto.h>

#include "openssl-support.hpp"
#include "stm32mp-image-signer.hpp"
#include "utils.hpp"

namespace {

struct CliOptions {
    std::string keyDesc;
    std::string passphrase;
    std::string inputFile;
    std::string outputFile;
    std::string outputHash;
    std::string pkcs11Module;
    bool verbose = false;
    bool valid = true;
};

void usage(const std::string& argv0) {
    std::cout << "Usage: " << argv0 << " -k key_desc [-p passphrase/pin] [-m module_path] [-v] [-i input_file] [-o output_file] [-h hash_file]" << std::endl;
}

CliOptions parseCliOptions(int argc, char* argv[]) {
    CliOptions options;

    if (argc == 1) {
        usage(argv[0]);
        options.valid = false;
        return options;
    }

    int opt;
    while ((opt = getopt(argc, argv, "k:p:h:vi:o:m:")) != -1) {
        switch (opt) {
            case 'k':
                options.keyDesc = optarg;
                break;
            case 'p':
                options.passphrase = optarg;
                break;
            case 'v':
                options.verbose = true;
                break;
            case 'h':
                options.outputHash = optarg;
                break;
            case 'i':
                options.inputFile = optarg;
                break;
            case 'o':
                options.outputFile = optarg;
                break;
            case 'm':
                options.pkcs11Module = optarg;
                break;
            default:
                usage(argv[0]);
                options.valid = false;
                return options;
        }
    }

    return options;
}

} // namespace

/*******************************************************************
 * https://wiki.st.com/stm32mpu/wiki/STM32_header_for_binary_files *
 *                                                                 *
 * The STM32 binary header exists in several versions, identified  *
 * by the major byte of the hdr_version field:                     *
 * - v1.x (256 bytes): STM32MP15x lines                            *
 * - v2.x (512 bytes): STM32MP13x lines and STM32MP2 series,       *
 *   with extension headers (not implemented yet)                  *
 *                                                                 *
 * Notes (v1):                                                     *
 * - The signature is calculated over the data starting at offset  *
 *   0x48 (hdr_version field) up to the last byte given by the     *
 *   image_length field (i.e. sizeof(header) + header.length).     *
 * - The ecdsa_pubkey contains the public key (x, y) coordinates   *
 *   of the ECDSA key (64 bytes total).                            *
 *******************************************************************/

int main(int argc, char* argv[]) {
    auto utils = std::make_shared<Utils>();
    auto openSslSupport = std::make_shared<OpenSSLSupport>();

    CliOptions options = parseCliOptions(argc, argv);
    if (!options.valid) {
        return -1;
    }

    utils->setVerbose(options.verbose);
    if (!options.pkcs11Module.empty()) {
        openSslSupport->setPkcs11Module(options.pkcs11Module);
    }

    if (options.keyDesc.empty()) {
        std::cerr << "Must specify a key file or pkcs11 uri" << std::endl;
        return -1;
    }

    if (!options.inputFile.empty()) {
        STM32MPImageSigner imageSigner(openSslSupport, utils);
        std::ifstream imageFile(options.inputFile, std::ios::binary);
        std::vector<unsigned char> image((std::istreambuf_iterator<char>(imageFile)), std::istreambuf_iterator<char>());
        imageFile.close();

        if (imageSigner.signImage(image, options.keyDesc, options.passphrase) != 0) {
            return -1;
        }

        if (!options.outputFile.empty()) {
            std::ofstream output(options.outputFile, std::ios::binary);
            output.write((const char*)image.data(), static_cast<std::streamsize>(image.size()));
            output.close();
        }
    }

    if (!options.outputHash.empty()) {
        if (openSslSupport->hashPubkey(options.keyDesc, options.passphrase, options.outputHash, *utils) != 0) {
            return -1;
        }
    }

    // Securely erase the passphrase
    if (!options.passphrase.empty()) {
        OPENSSL_cleanse(options.passphrase.data(), options.passphrase.size());
    }

    // Securely erase the key_desc in case it's a pkcs11 uri with pin
    if (!options.keyDesc.empty()) {
        OPENSSL_cleanse(options.keyDesc.data(), options.keyDesc.size());
    }

    return 0;
}
