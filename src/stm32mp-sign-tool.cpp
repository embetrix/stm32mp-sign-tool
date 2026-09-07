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
#include <optional>
#include <string>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <openssl/crypto.h>

#include "openssl-support.hpp"
#include "stm32mp-image-signer.hpp"
#include "utils.hpp"

namespace {

struct CliOptions {
    std::string keyDesc;
    // Empty and absent are different things: an absent passphrase lets OpenSSL
    // prompt, an empty one is a real (empty) password. Do not collapse them.
    std::optional<std::string> passphrase;
    std::string inputFile;
    std::string outputFile;
    std::string outputHash;
    std::string pkcs11Module;
    bool verbose = false;
    bool valid = true;

    // The originals these were copied from, still sitting in argv[] where
    // ps(1) and /proc/self/cmdline expose them to every other user on the box.
    // The copies above are not the only thing that has to be wiped.
    char* keyDescArg = nullptr;
    char* passphraseArg = nullptr;
};

void cleanse(char* arg) {
    if (arg != nullptr) {
        OPENSSL_cleanse(arg, std::strlen(arg));
    }
}

void cleanse(std::string& str) {
    if (!str.empty()) {
        OPENSSL_cleanse(str.data(), str.size());
    }
}

// Wipes the key descriptor (which may be a PKCS#11 URI carrying a PIN) and the
// passphrase on every exit path out of main(), copies and argv[] originals alike.
class SecretScrubber {
public:
    explicit SecretScrubber(CliOptions& options) : options(options) {}
    SecretScrubber(const SecretScrubber&) = delete;
    SecretScrubber& operator=(const SecretScrubber&) = delete;

    ~SecretScrubber() {
        if (options.passphrase) {
            cleanse(*options.passphrase);
        }
        cleanse(options.keyDesc);
        cleanse(options.passphraseArg);
        cleanse(options.keyDescArg);
    }

private:
    CliOptions& options;
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
                options.keyDescArg = optarg;
                break;
            case 'p':
                options.passphrase = optarg;
                options.passphraseArg = optarg;
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
    SecretScrubber scrubber(options);
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

    return 0;
}
