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
#include <stdexcept>
#include <cstdint>
#include <iomanip>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <openssl/store.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/ui.h>

#define STM32_MAGIC "STM2" // 0x53544D32

static bool verbose = false;
static const char* pkcs11_module = nullptr;
static OSSL_PROVIDER* pkcs11_provider = nullptr;
static OSSL_PROVIDER* default_provider = nullptr;

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

// Fields common to all STM32 header versions (offsets 0x00-0x63)
struct STM32HeaderCommon {
    char magic[4];
    unsigned char signature[64];
    uint32_t checksum;
    uint32_t hdr_version; // byte 1: minor, byte 2: major
    uint32_t length;
    uint32_t entry_addr;
    uint32_t reserved1; // Set to 0
    uint32_t load_addr;
    uint32_t reserved2; // Set to 0
    uint32_t rollback_version;
} __attribute__((packed));

// Header v1 (STM32MP15x lines)
struct STM32HeaderV1 {
    char magic[4];
    unsigned char signature[64];
    uint32_t checksum;
    uint32_t hdr_version;
    uint32_t length;
    uint32_t entry_addr;
    uint32_t reserved1; // Set to 0
    uint32_t load_addr;
    uint32_t reserved2; // Set to 0
    uint32_t rollback_version;
    uint32_t option_flags;
    uint32_t ecdsa_algo;
    unsigned char ecdsa_pubkey[64];
    unsigned char padding[83];
    unsigned char binary_type;
} __attribute__((packed));

enum STM32HeaderVersion {
    STM32_HEADER_V1 = 1, // STM32MP15x lines
    STM32_HEADER_V2 = 2, // STM32MP13x lines and STM32MP2 series
};

// Validate the common header fields and return the header major version,
// or -1 if the image is too short or does not carry the STM32 magic.
int get_stm32_header_version(const std::vector<unsigned char>& image) {
    if (image.size() < sizeof(STM32HeaderCommon)) {
        std::cerr << "Image too short for an STM32 header: got " << image.size() << " bytes" << std::endl;
        return -1;
    }
    STM32HeaderCommon common;
    std::memcpy(&common, image.data(), sizeof(common));
    if (std::strncmp(common.magic, STM32_MAGIC, sizeof(common.magic)) != 0) {
        std::cerr << "Not an STM32 header (signature FAIL): expected magic '" << STM32_MAGIC
                  << "', got '" << std::string(common.magic, sizeof(common.magic)) << "'" << std::endl;
        return -1;
    }
    return (common.hdr_version >> 16) & 0xFF;
}

STM32HeaderV1 unpack_stm32_header_v1(const std::vector<unsigned char>& image) {
    STM32HeaderV1 header;
    std::memcpy(&header, image.data(), sizeof(STM32HeaderV1));
    return header;
}

void repack_stm32_header_v1(std::vector<unsigned char>& image, const STM32HeaderV1& header) {
    std::memcpy(image.data(), &header, sizeof(STM32HeaderV1));
}

void print_hex(const std::string& label, const std::vector<unsigned char>& data) {
    if (!verbose) 
        return;
    std::cout << label << ": ";
    for (unsigned char byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
}

int get_ec_pubkey(const unsigned char* pubkey, size_t pubkey_len, uint32_t algo, EVP_PKEY** pkey) {
    *pkey = nullptr;
    if (!pubkey) {
        std::cerr << "Public key is empty" << std::endl;
        return -1;
    }
    if (pubkey_len != 64) {
        std::cerr << "Invalid public key length" << std::endl;
        return -1;
    }
    const char* group_name;
    if (algo == 1) {
        group_name = SN_X9_62_prime256v1;
    } else if (algo == 2) {
        group_name = SN_brainpoolP256t1;
    } else {
        std::cerr << "Unsupported ECDSA algorithm" << std::endl;
        return -1;
    }

    // Build the uncompressed EC point: 0x04 || X || Y
    std::vector<unsigned char> point(1 + pubkey_len);
    point[0] = 0x04;
    std::memcpy(point.data() + 1, pubkey, pubkey_len);

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        std::cerr << "Failed to create OSSL_PARAM_BLD" << std::endl;
        return -1;
    }
    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                         group_name, 0) ||
        !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                          point.data(), point.size())) {
        std::cerr << "Failed to set public key parameters" << std::endl;
        OSSL_PARAM_BLD_free(bld);
        return -1;
    }
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) {
        std::cerr << "Failed to build public key parameters" << std::endl;
        return -1;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    int ret = -1;
    if (ctx &&
        EVP_PKEY_fromdata_init(ctx) > 0 &&
        EVP_PKEY_fromdata(ctx, pkey, EVP_PKEY_PUBLIC_KEY, params) > 0) {
        ret = 0;
    } else {
        std::cerr << "Failed to create EVP_PKEY from public key" << std::endl;
        *pkey = nullptr;
    }
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    return ret;
}

std::vector<unsigned char> get_raw_pubkey(EVP_PKEY* key) {
    if (!key) {
        std::cerr << "Invalid EVP_PKEY" << std::endl;
        return {};
    }
    // Export the public key params. Unlike the per-parameter getters,
    // EVP_PKEY_todata works uniformly across the default provider (file
    // keys) and the PKCS#11 provider, which only implements key export.
    OSSL_PARAM* params = nullptr;
    if (EVP_PKEY_todata(key, EVP_PKEY_PUBLIC_KEY, &params) != 1 || !params) {
        std::cerr << "Failed to export public key from EVP_PKEY" << std::endl;
        return {};
    }

    std::vector<unsigned char> pubkey;
    const OSSL_PARAM* pub = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (pub && pub->data_size == 65) {
        // Uncompressed EC point: 0x04 || X || Y
        const unsigned char* point = static_cast<const unsigned char*>(pub->data);
        if (point[0] == 0x04) {
            pubkey.assign(point + 1, point + pub->data_size);
        }
    }

    OSSL_PARAM_free(params);
    if (pubkey.empty()) {
        std::cerr << "Unexpected public key encoding" << std::endl;
    }
    return pubkey;
}

int get_key_algorithm(EVP_PKEY* key) {
    if (!key) {
        std::cerr << "Invalid EVP_PKEY" << std::endl;
        return -1;
    }
    char group_name[64];
    size_t len = 0;
    if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME,
                                       group_name, sizeof(group_name), &len) != 1) {
        std::cerr << "Failed to get EC group name" << std::endl;
        return -1;
    }
    if (std::strcmp(group_name, SN_X9_62_prime256v1) == 0) {
        return 1;
    }
    else if (std::strcmp(group_name, SN_brainpoolP256t1) == 0) {
        return 2;
    }
    std::cerr << "Unsupported ECDSA curve: " << group_name << std::endl;
    return -1;
}

// UI_METHOD reader callback used to feed the PKCS#11 PIN (or PEM passphrase)
// stored as user data to OSSL_STORE without prompting interactively.
static int ui_read_string(UI* ui, UI_STRING* uis) {
    switch (UI_get_string_type(uis)) {
        case UIT_PROMPT:
        case UIT_VERIFY: {
            const char* secret = static_cast<const char*>(UI_get0_user_data(ui));
            if (secret) {
                return UI_set_result(ui, uis, secret) >= 0 ? 1 : 0;
            }
            return 1;
        }
        default:
            return 1;
    }
}

int load_key(const char* key_desc, const char* passphrase, EVP_PKEY** pkey) {
    *pkey = nullptr;
    if (!key_desc || std::strlen(key_desc) == 0) {
        std::cerr << "Invalid arguments" << std::endl;
        return -1;
    }

    if (std::strncmp(key_desc, "pkcs11:", 7) == 0) {
        // Load key using the PKCS#11 provider via OSSL_STORE.

        // Allow overriding the PKCS#11 module through the provider's
        // environment variable before the provider is loaded.
        if (pkcs11_module) {
            setenv("PKCS11_PROVIDER_MODULE", pkcs11_module, 1);
        }

        // The default provider is required alongside pkcs11 (e.g. for hashing).
        if (!default_provider) {
            default_provider = OSSL_PROVIDER_load(nullptr, "default");
        }
        if (!pkcs11_provider) {
            pkcs11_provider = OSSL_PROVIDER_load(nullptr, "pkcs11");
        }
        if (!pkcs11_provider) {
            std::cerr << "Failed to load PKCS#11 provider" << std::endl;
            return -1;
        }

        UI_METHOD* ui_method = nullptr;
        if (passphrase) {
            ui_method = UI_create_method("stm32mp-sign-tool pin reader");
            if (!ui_method || UI_method_set_reader(ui_method, ui_read_string) != 0) {
                std::cerr << "Failed to set up PIN reader" << std::endl;
                if (ui_method) UI_destroy_method(ui_method);
                return -1;
            }
        }

        OSSL_STORE_CTX* store = OSSL_STORE_open(key_desc, ui_method,
                                                const_cast<char*>(passphrase),
                                                nullptr, nullptr);
        if (!store) {
            std::cerr << "Failed to open PKCS#11 store: " << key_desc << std::endl;
            if (ui_method) UI_destroy_method(ui_method);
            return -1;
        }

        // Look for the private key in the store.
        OSSL_STORE_expect(store, OSSL_STORE_INFO_PKEY);
        while (!OSSL_STORE_eof(store)) {
            OSSL_STORE_INFO* info = OSSL_STORE_load(store);
            if (!info) {
                if (OSSL_STORE_error(store)) {
                    continue;
                }
                break;
            }
            if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
                *pkey = OSSL_STORE_INFO_get1_PKEY(info);
                OSSL_STORE_INFO_free(info);
                break;
            }
            OSSL_STORE_INFO_free(info);
        }

        OSSL_STORE_close(store);
        if (ui_method) UI_destroy_method(ui_method);

        if (!*pkey) {
            std::cerr << "Failed to load private key from PKCS#11: " << key_desc << std::endl;
            return -1;
        }
    }
    else {
        // Load key from file
        FILE* key_fp = fopen(key_desc, "r");
        if (!key_fp) {
            std::cerr << "Failed to open key file" << std::endl;
            return -1;
        }

        *pkey = PEM_read_PrivateKey(key_fp, nullptr, nullptr,
                                    static_cast<void*>(const_cast<char*>(passphrase)));
        fclose(key_fp);
        if (!*pkey) {
            std::cerr << "Failed to read key from file" << std::endl;
            return -1;
        }
    }

    return 0;
}

int hash_pubkey(const char* key_desc, const char* passphrase, const std::string &output_file) {
    if (!key_desc || output_file.empty()) {
        std::cerr << "Invalid arguments" << std::endl;
        return -1;
    }
    EVP_PKEY* key = nullptr;
    if (load_key(key_desc, passphrase, &key) != 0) {
        std::cerr << "Failed to load key: " << key_desc << std::endl;
        return -1;
    }
    if (!key) {
        std::cerr << "Invalid key" << std::endl;
        return -1;
    }
    std::vector<unsigned char> pubkey = get_raw_pubkey(key);
    if (pubkey.empty()) {
        std::cerr << "Failed to get raw public key" << std::endl;
        EVP_PKEY_free(key);
        return -1;
    }
    EVP_PKEY_free(key);

    std::vector<unsigned char> phash(SHA256_DIGEST_LENGTH);
    SHA256(pubkey.data(), pubkey.size(), phash.data());
    print_hex("Pubkey(sha256)", phash);

    std::ofstream output(output_file, std::ios::binary);
    if (!output) {
        std::cerr << "Failed to open output file: " << output_file << std::endl;
        return -1;
    }
    output.write(reinterpret_cast<const char*>(phash.data()), static_cast<std::streamsize>(phash.size()));
    output.close();

    return 0;
 
}

int verify_stm32_image_v1(const std::vector<unsigned char>& image) {
    if (image.size() < sizeof(STM32HeaderV1)) {
        std::cerr << "Image too short for an STM32 v1 header: got " << image.size() << " bytes" << std::endl;
        return -1;
    }
    STM32HeaderV1 header = unpack_stm32_header_v1(image);

    // The ROM code hashes exactly 'header.length' bytes after the header (256 bytes), so we must not include trailing padding.
    size_t hash_end = sizeof(STM32HeaderV1) + header.length;
    if (hash_end > image.size()) {
        std::cerr << "Image too short: expected at least " << hash_end << " bytes, got " << image.size() << std::endl;
        return -1;
    }
    std::vector<unsigned char> buffer_to_hash(image.begin() + offsetof(STM32HeaderV1, hdr_version), image.begin() + static_cast<std::ptrdiff_t>(hash_end));
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    if (!SHA256(buffer_to_hash.data(), buffer_to_hash.size(), hash.data())) {
        std::cerr << "Failed to compute SHA-256 hash" << std::endl;
        return -1;
    }
    std::vector<unsigned char> signature(header.signature, header.signature + sizeof(header.signature));
    print_hex("Hash", hash);
    print_hex("Signature", signature);

    ECDSA_SIG* sig = ECDSA_SIG_new();

    if (!sig) {
        std::cerr << "Failed to create ECDSA_SIG structure" << std::endl;
        return -1;
    }

    // Extract r and s from the signature buffer
    BIGNUM* r = BN_bin2bn(signature.data(), sizeof(header.signature) / 2, nullptr);
    BIGNUM* s = BN_bin2bn(signature.data() + sizeof(header.signature) / 2, sizeof(header.signature) / 2, nullptr);
    if (!r || !s) {
        if (r) BN_free(r);
        if (s) BN_free(s);
        std::cerr << "Failed to create BIGNUMs for r and s" << std::endl;
        ECDSA_SIG_free(sig);
        return -1;
    }

    if (ECDSA_SIG_set0(sig, r, s) == 0) {
        std::cerr << "Failed to set r and s in ECDSA_SIG" << std::endl;
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return -1;
    }

    // EVP_DigestVerify expects a DER-encoded ECDSA signature.
    unsigned char* der = nullptr;
    int der_len = i2d_ECDSA_SIG(sig, &der);
    ECDSA_SIG_free(sig);
    if (der_len <= 0) {
        std::cerr << "Failed to DER-encode signature" << std::endl;
        return -1;
    }

    EVP_PKEY* pubkey = nullptr;
    if (get_ec_pubkey(header.ecdsa_pubkey, sizeof(header.ecdsa_pubkey), header.ecdsa_algo, &pubkey) != 0) {
        std::cerr << "Failed to get EVP_PKEY from public key" << std::endl;
        OPENSSL_free(der);
        return -1;
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    int verify_status = -1;
    if (md_ctx &&
        EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, pubkey) == 1) {
        verify_status = EVP_DigestVerify(md_ctx, der, static_cast<size_t>(der_len),
                                         buffer_to_hash.data(), buffer_to_hash.size());
    }
    EVP_MD_CTX_free(md_ctx);
    OPENSSL_free(der);
    EVP_PKEY_free(pubkey);

    if (verify_status == 1) {
        return 0;
    } else {
        std::cerr << "Signature does not match: " << verify_status << std::endl;
        return -1;
    }
}

int verify_stm32_image(const std::vector<unsigned char>& image) {
    int hdr_version = get_stm32_header_version(image);
    switch (hdr_version) {
        case STM32_HEADER_V1:
            return verify_stm32_image_v1(image);
        case STM32_HEADER_V2:
            std::cerr << "STM32 header v2 (STM32MP13x lines and STM32MP2 series) is not supported yet" << std::endl;
            return -1;
        case -1:
            return -1;
        default:
            std::cerr << "Unknown STM32 header version: " << hdr_version << std::endl;
            return -1;
    }
}

int sign_stm32_image_v1(std::vector<unsigned char>& image, const char* key_desc, const char* passphrase) {
    if (image.size() < sizeof(STM32HeaderV1)) {
        std::cerr << "Image too short for an STM32 v1 header: got " << image.size() << " bytes" << std::endl;
        return -1;
    }
    EVP_PKEY* key = nullptr;
    if (load_key(key_desc, passphrase, &key) != 0) {
        std::cerr << "Failed to load key: " << key_desc << std::endl;
        return -1;
    }

    STM32HeaderV1 header = unpack_stm32_header_v1(image);

    // Ensure reserved fields are set to 0
    header.reserved1 = 0;
    header.reserved2 = 0;


    // Get the public key from the private key
    std::vector<unsigned char> pubkey = get_raw_pubkey(key);
    if (pubkey.empty()) {
        EVP_PKEY_free(key);
        return -1;
    }
    print_hex("Public Key", pubkey);

    std::memcpy(header.ecdsa_pubkey, pubkey.data(), pubkey.size());
    int algo = get_key_algorithm(key);
    if (algo < 0) {
        EVP_PKEY_free(key);
        return -1;
    }
    header.ecdsa_algo = static_cast<uint32_t>(algo);
    header.option_flags = 0;
    std::memset(header.padding, 0, sizeof(header.padding)); // Ensure padding is zeroed
    repack_stm32_header_v1(image, header);

    // The ROM code hashes exactly 'header.length' bytes after the header (256 bytes), so we must not include trailing padding.
    size_t hash_end = sizeof(STM32HeaderV1) + header.length;
    if (hash_end > image.size()) {
        std::cerr << "Image too short: expected at least " << hash_end << " bytes, got " << image.size() << std::endl;
        EVP_PKEY_free(key);
        return -1;
    }
    std::vector<unsigned char> buffer_to_hash(image.begin() + offsetof(STM32HeaderV1, hdr_version), image.begin() + static_cast<std::ptrdiff_t>(hash_end));

    // Sign with the high-level EVP interface so that provider-backed keys
    // (e.g. non-extractable PKCS#11 keys) sign in-place. This produces a
    // DER-encoded ECDSA signature.
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    std::vector<unsigned char> der;
    size_t der_len = 0;
    if (!md_ctx ||
        EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, key) != 1 ||
        EVP_DigestSign(md_ctx, nullptr, &der_len, buffer_to_hash.data(), buffer_to_hash.size()) != 1) {
        std::cerr << "Failed to initialize signing" << std::endl;
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(key);
        return -1;
    }
    der.resize(der_len);
    if (EVP_DigestSign(md_ctx, der.data(), &der_len, buffer_to_hash.data(), buffer_to_hash.size()) != 1) {
        std::cerr << "Failed to sign the image" << std::endl;
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(key);
        return -1;
    }
    der.resize(der_len);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(key);

    // Decode the DER signature back to (r, s) to build the fixed-size raw
    // signature expected in the STM32 header.
    const unsigned char* der_ptr = der.data();
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &der_ptr, static_cast<long>(der_len));
    if (sig == nullptr) {
        std::cerr << "Failed to decode ECDSA signature" << std::endl;
        return -1;
    }

    const BIGNUM* r;
    const BIGNUM* s;
    ECDSA_SIG_get0(sig, &r, &s);

    std::vector<unsigned char> r_bytes(static_cast<size_t>(BN_num_bytes(r)));
    std::vector<unsigned char> s_bytes(static_cast<size_t>(BN_num_bytes(s)));
    if (BN_bn2binpad(r, r_bytes.data(), static_cast<int>(r_bytes.size())) < 0 || BN_bn2binpad(s, s_bytes.data(), static_cast<int>(s_bytes.size())) < 0) {
        std::cerr << "Failed to convert BIGNUM to binary" << std::endl;
        ECDSA_SIG_free(sig);
        return -1;
    }
    print_hex("ECC key(r)", r_bytes);
    print_hex("ECC key(s)", s_bytes);

    std::vector<unsigned char> signature(sizeof(header.signature));
    std::memset(signature.data(), 0, signature.size());
    std::memcpy(signature.data() + (sizeof(header.signature) / 2 - r_bytes.size()), r_bytes.data(), r_bytes.size());
    std::memcpy(signature.data() + sizeof(header.signature) - s_bytes.size(), s_bytes.data(), s_bytes.size());
    print_hex("Signature", signature);

    std::memcpy(image.data() + offsetof(STM32HeaderV1, signature), signature.data(), signature.size());
    ECDSA_SIG_free(sig);

    // Verify the signature
    return verify_stm32_image_v1(image);

}

int sign_stm32_image(std::vector<unsigned char>& image, const char* key_desc, const char* passphrase) {
    if (image.empty()) {
        std::cerr << "Image data is empty" << std::endl;
        return -1;
    }
    if (!key_desc || std::strlen(key_desc) == 0) {
        std::cerr << "Key file path is empty" << std::endl;
        return -1;
    }
    int hdr_version = get_stm32_header_version(image);
    switch (hdr_version) {
        case STM32_HEADER_V1:
            if (verbose) {
                std::cout << "STM32 header v1 (STM32MP15x lines)" << std::endl;
            }
            return sign_stm32_image_v1(image, key_desc, passphrase);
        case STM32_HEADER_V2:
            std::cerr << "STM32 header v2 (STM32MP13x lines and STM32MP2 series) is not supported yet" << std::endl;
            return -1;
        case -1:
            return -1;
        default:
            std::cerr << "Unknown STM32 header version: " << hdr_version << std::endl;
            return -1;
    }
}

void usage(const char* argv0) {
    std::cout << "Usage: " << argv0 << " -k key_desc [-p passphrase/pin] [-m module_path] [-v] [-i input_file] [-o output_file] [-h hash_file]" << std::endl;
}

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
                verbose = true;
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
                pkcs11_module = optarg;
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

    if (pkcs11_provider) {
        OSSL_PROVIDER_unload(pkcs11_provider);
    }
    if (default_provider) {
        OSSL_PROVIDER_unload(default_provider);
    }

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
