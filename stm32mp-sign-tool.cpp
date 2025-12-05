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
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <openssl/engine.h>

#define STM32_MAGIC "STM2" // 0x53544D32

static bool verbose = false;
static ENGINE* engine = nullptr;

/*******************************************************************
 * https://wiki.st.com/stm32mpu/wiki/STM32_header_for_binary_files *
 *                                                                 *
 * Notes:                                                          *
 * - The signature is calculated over the data starting at offset  *
 *   0x48 (hdr_version field) up to the last byte given by the     *
 *   image_length field (i.e. sizeof(header) + header.length).     *
 * - The ecdsa_pubkey contains the public key (x, y) coordinates   *
 *   of the ECDSA key (64 bytes total).                            *
 *******************************************************************/
struct STM32Header {
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

STM32Header unpack_stm32_header(const std::vector<unsigned char>& image) {
    STM32Header header;
    std::memcpy(&header, image.data(), sizeof(STM32Header));
    return header;
}

void repack_stm32_header(std::vector<unsigned char>& image, const STM32Header& header) {
    std::memcpy(image.data(), &header, sizeof(STM32Header));
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

int get_ec_pubkey(const unsigned char* pubkey, size_t pubkey_len, uint32_t algo, EC_KEY** ec_key) {
    if (!pubkey) {
        std::cerr << "Public key is empty" << std::endl;
        return -1;
    }
    if (pubkey_len != 64) {
        std::cerr << "Invalid public key length" << std::endl;
        return -1;
    }
    int curve_nid;
    if (algo == 1) {
        curve_nid = NID_X9_62_prime256v1;
    } else if (algo == 2) {
        curve_nid = NID_brainpoolP256t1;
    } else {
        std::cerr << "Unsupported ECDSA algorithm" << std::endl;
        return -1;
    }
    *ec_key = EC_KEY_new_by_curve_name(curve_nid);
    if (!*ec_key) {
        std::cerr << "Failed to create EC_KEY object" << std::endl;
        return -1;
    }

    BIGNUM* x = BN_bin2bn(pubkey, 32, nullptr);
    BIGNUM* y = BN_bin2bn(pubkey + 32, 32, nullptr);
    if (!x || !y) {
        std::cerr << "Failed to create BIGNUMs for public key coordinates" << std::endl;
        if (x) BN_free(x);
        if (y) BN_free(y);
        EC_KEY_free(*ec_key);
        *ec_key = nullptr;
        return -1;
    }

    EC_POINT* point = EC_POINT_new(EC_KEY_get0_group(*ec_key));
    if (!point) {
        std::cerr << "Failed to create EC_POINT object" << std::endl;
        BN_free(x);
        BN_free(y);
        EC_KEY_free(*ec_key);
        *ec_key = nullptr;
        return -1;
    }

    if (!EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(*ec_key), point, x, y, nullptr)) {
        std::cerr << "Failed to set affine coordinates" << std::endl;
        BN_free(x);
        BN_free(y);
        EC_POINT_free(point);
        EC_KEY_free(*ec_key);
        *ec_key = nullptr;
        return -1;
    }

    if (!EC_KEY_set_public_key(*ec_key, point)) {
        std::cerr << "Failed to set public key" << std::endl;
        BN_free(x);
        BN_free(y);
        EC_POINT_free(point);
        EC_KEY_free(*ec_key);
        *ec_key = nullptr;
        return -1;
    }

    BN_free(x);
    BN_free(y);
    EC_POINT_free(point);

    if (!EC_KEY_check_key(*ec_key)) {
        std::cerr << "Invalid EC key" << std::endl;
        EC_KEY_free(*ec_key);
        *ec_key = nullptr;
        return -1;
    }

    return 0;
}

std::vector<unsigned char> get_raw_pubkey(EC_KEY* key) {
    if (!key) {
        std::cerr << "Invalid EC_KEY" << std::endl;
        return {};
    }
    const EC_POINT* point = EC_KEY_get0_public_key(key);
    const EC_GROUP* group = EC_KEY_get0_group(key);
    std::vector<unsigned char> pubkey(64);
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    if (!x || !y) {
        if (x) BN_free(x);
        if (y) BN_free(y);
        std::cerr << "Failed to allocate BIGNUM" << std::endl;
        return {};
    }
    if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, nullptr)) {
        BN_free(x);
        BN_free(y);
        std::cerr << "Failed to get affine coordinates" << std::endl;
        return {};
    }
    if (BN_bn2binpad(x, pubkey.data(), 32) != 32 || BN_bn2binpad(y, pubkey.data() + 32, 32) != 32) {
        BN_free(x);
        BN_free(y);
        std::cerr << "Failed to convert BIGNUM to binary" << std::endl;
        return {};
    }
    BN_free(x);
    BN_free(y);
    return pubkey;
}

int get_key_algorithm(EC_KEY* key) {
    if (!key) {
        std::cerr << "Invalid EC_KEY" << std::endl;
        return -1;
    }
    const EC_GROUP* group = EC_KEY_get0_group(key);
    int nid = EC_GROUP_get_curve_name(group);
    if (nid == NID_X9_62_prime256v1) {
        return 1;
    }
    else if (nid == NID_brainpoolP256t1) {
        return 2;
    }
    std::cerr << "Unsupported ECDSA curve" << std::endl;
    return -1;
}

// Parse DER-encoded ECDSA signature and convert to raw 64-byte format (32 bytes r + 32 bytes s)
// DER format: 0x30 <len> 0x02 <r_len> <r> 0x02 <s_len> <s>
std::vector<unsigned char> parse_der_signature(const std::vector<unsigned char>& der_sig) {
    if (der_sig.size() < 8) {
        std::cerr << "DER signature too short" << std::endl;
        return {};
    }

    // Check if it's already raw format (64 bytes)
    if (der_sig.size() == 64) {
        // Assume it's already in raw format
        return der_sig;
    }

    // Check DER header
    if (der_sig[0] != 0x30) {
        std::cerr << "Invalid DER signature: missing SEQUENCE tag" << std::endl;
        return {};
    }

    size_t idx = 2; // Skip 0x30 and length byte

    // Parse r
    if (idx >= der_sig.size() || der_sig[idx] != 0x02) {
        std::cerr << "Invalid DER signature: missing INTEGER tag for r" << std::endl;
        return {};
    }
    idx++;

    if (idx >= der_sig.size()) {
        std::cerr << "Invalid DER signature: truncated" << std::endl;
        return {};
    }

    size_t r_len = der_sig[idx++];
    if (idx + r_len > der_sig.size()) {
        std::cerr << "Invalid DER signature: r length exceeds data" << std::endl;
        return {};
    }

    std::vector<unsigned char> r_bytes(der_sig.begin() + static_cast<std::ptrdiff_t>(idx), der_sig.begin() + static_cast<std::ptrdiff_t>(idx + r_len));
    idx += r_len;

    // Parse s
    if (idx >= der_sig.size() || der_sig[idx] != 0x02) {
        std::cerr << "Invalid DER signature: missing INTEGER tag for s" << std::endl;
        return {};
    }
    idx++;

    if (idx >= der_sig.size()) {
        std::cerr << "Invalid DER signature: truncated" << std::endl;
        return {};
    }

    size_t s_len = der_sig[idx++];
    if (idx + s_len > der_sig.size()) {
        std::cerr << "Invalid DER signature: s length exceeds data" << std::endl;
        return {};
    }

    std::vector<unsigned char> s_bytes(der_sig.begin() + static_cast<std::ptrdiff_t>(idx), der_sig.begin() + static_cast<std::ptrdiff_t>(idx + s_len));

    // Remove leading zero bytes (DER encoding adds 0x00 for positive numbers with MSB set)
    while (r_bytes.size() > 32 && r_bytes[0] == 0x00) {
        r_bytes.erase(r_bytes.begin());
    }
    while (s_bytes.size() > 32 && s_bytes[0] == 0x00) {
        s_bytes.erase(s_bytes.begin());
    }

    // Check if r and s fit in 32 bytes
    if (r_bytes.size() > 32 || s_bytes.size() > 32) {
        std::cerr << "Invalid DER signature: r or s too large (r=" << r_bytes.size()
                  << ", s=" << s_bytes.size() << ")" << std::endl;
        return {};
    }

    // Create 64-byte raw signature (32 bytes r + 32 bytes s)
    std::vector<unsigned char> raw_sig(64, 0);

    // Copy r (right-aligned in first 32 bytes)
    std::copy(r_bytes.begin(), r_bytes.end(), raw_sig.begin() + static_cast<std::ptrdiff_t>(32 - r_bytes.size()));

    // Copy s (right-aligned in second 32 bytes)
    std::copy(s_bytes.begin(), s_bytes.end(), raw_sig.begin() + static_cast<std::ptrdiff_t>(32 + (32 - s_bytes.size())));

    return raw_sig;
}

int load_private_key(const char* key_desc, const char* passphrase, EC_KEY** ec_key) {
    *ec_key = nullptr;
    if (!key_desc || std::strlen(key_desc) == 0) {
        std::cerr << "Invalid arguments" << std::endl;
        return -1;
    }
    if (std::strncmp(key_desc, "pkcs11:", 7) == 0) {
        // Load key using PKCS#11

        // Load the engine
        ENGINE_load_builtin_engines();
        engine = ENGINE_by_id("pkcs11");
        if (!engine) {
            std::cerr << "Failed to load PKCS#11 engine" << std::endl;
            return -1;
        }

        // Initialize the engine
        if (!ENGINE_init(engine)) {
            ENGINE_free(engine);
            std::cerr << "Failed to initialize PKCS#11 engine" << std::endl;
            return -1;
        }

        // Set the PIN
        if (passphrase && !ENGINE_ctrl_cmd_string(engine, "PIN", passphrase, 0)) {
            ENGINE_finish(engine);
            ENGINE_free(engine);
            std::cerr << "Failed to set PKCS#11 PIN" << std::endl;
            return -1;
        }

        // Load the private key
        EVP_PKEY* pkey = ENGINE_load_private_key(engine, key_desc, nullptr, nullptr);
        if (!pkey) {
            ENGINE_finish(engine);
            ENGINE_free(engine);
            std::cerr << "Failed to load private key from PKCS#11" << std::endl;
            return -1;
        }

        // Extract the EC_KEY from the EVP_PKEY
        *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
        EVP_PKEY_free(pkey);

        if (!*ec_key) {
            ENGINE_finish(engine);
            ENGINE_free(engine);
            std::cerr << "Failed to extract EC_KEY from EVP_PKEY" << std::endl;
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

        *ec_key = PEM_read_ECPrivateKey(key_fp, nullptr, nullptr, static_cast<void*>(const_cast<char*>(passphrase)));
        fclose(key_fp);
        if (!*ec_key) {
            std::cerr << "Failed to read key from file" << std::endl;
            return -1;
        }
    }

    return 0;
}

int load_public_key(const char* key_desc, const char* passphrase, EC_KEY** ec_key) {
    *ec_key = nullptr;
    if (!key_desc || std::strlen(key_desc) == 0) {
        std::cerr << "Invalid arguments" << std::endl;
        return -1;
    }

    if (std::strncmp(key_desc, "pkcs11:", 7) == 0) {
        // Load key using PKCS#11

        // Load the engine
        ENGINE_load_builtin_engines();
        engine = ENGINE_by_id("pkcs11");
        if (!engine) {
            std::cerr << "Failed to load PKCS#11 engine" << std::endl;
            return -1;
        }

        // Initialize the engine
        if (!ENGINE_init(engine)) {
            ENGINE_free(engine);
            std::cerr << "Failed to initialize PKCS#11 engine" << std::endl;
            return -1;
        }

        // Set the PIN
        if (passphrase && !ENGINE_ctrl_cmd_string(engine, "PIN", passphrase, 0)) {
            ENGINE_finish(engine);
            ENGINE_free(engine);
            std::cerr << "Failed to set PKCS#11 PIN" << std::endl;
            return -1;
        }

        // Load the public key
        EVP_PKEY* pkey = ENGINE_load_public_key(engine, key_desc, nullptr, nullptr);
        if (!pkey) {
            ENGINE_finish(engine);
            ENGINE_free(engine);
            std::cerr << "Failed to load public key from PKCS#11" << std::endl;
            return -1;
        }

        // Extract the EC_KEY from the EVP_PKEY
        *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
        EVP_PKEY_free(pkey);

        if (!*ec_key) {
            ENGINE_finish(engine);
            ENGINE_free(engine);
            std::cerr << "Failed to extract EC_KEY from EVP_PKEY" << std::endl;
            return -1;
        }
    }
    else {
        // Load public key from file
        FILE* key_fp = fopen(key_desc, "r");
        if (!key_fp) {
            std::cerr << "Failed to open public key file" << std::endl;
            return -1;
        }

        *ec_key = PEM_read_EC_PUBKEY(key_fp, nullptr, nullptr, nullptr);
        fclose(key_fp);
        if (!*ec_key) {
            std::cerr << "Failed to read public key from file" << std::endl;
            return -1;
        }
    }

    return 0;
}

int hash_pubkey(const char* private_key_desc, const char* public_key_desc, const char* passphrase, const std::string &output_file) {
    if ((!private_key_desc && !public_key_desc) || output_file.empty()) {
        std::cerr << "Invalid arguments" << std::endl;
        return -1;
    }

    EC_KEY* key = nullptr;

    // Try to load public key first if provided
    if (public_key_desc && std::strlen(public_key_desc) > 0) {
        if (load_public_key(public_key_desc, passphrase, &key) != 0) {
            std::cerr << "Failed to load public key" << std::endl;
            return -1;
        }
    }
    // Otherwise load from private key
    else if (private_key_desc && std::strlen(private_key_desc) > 0) {
        if (load_private_key(private_key_desc, passphrase, &key) != 0) {
            std::cerr << "Failed to load private key" << std::endl;
            return -1;
        }
    }

    if (!key) {
        std::cerr << "Invalid key" << std::endl;
        return -1;
    }

    std::vector<unsigned char> pubkey = get_raw_pubkey(key);
    EC_KEY_free(key);

    if (pubkey.empty()) {
        std::cerr << "Failed to get raw public key" << std::endl;
        return -1;
    }

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

int verify_stm32_image(const std::vector<unsigned char>& image) {
    if (image.empty()) {
        std::cerr << "Image data is empty" << std::endl;
        return -1;
    }
    STM32Header header = unpack_stm32_header(image);

    if (std::strncmp(header.magic, STM32_MAGIC, sizeof(header.magic)) != 0) {
        std::cerr << "Not an STM32 header (signature FAIL)" << std::endl;
        return -1;
    }

    // The ROM code hashes exactly 'header.length' bytes after the header (256 bytes), so we must not include trailing padding.
    size_t hash_end = sizeof(STM32Header) + header.length;
    if (hash_end > image.size()) {
        std::cerr << "Image too short: expected at least " << hash_end << " bytes, got " << image.size() << std::endl;
        return -1;
    }
    std::vector<unsigned char> buffer_to_hash(image.begin() + offsetof(STM32Header, hdr_version), image.begin() + static_cast<std::ptrdiff_t>(hash_end));
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
    EC_KEY* pubkey = nullptr;
    if (get_ec_pubkey(header.ecdsa_pubkey, sizeof(header.ecdsa_pubkey), header.ecdsa_algo, &pubkey) != 0) {
        std::cerr << "Failed to get EC_KEY from public key" << std::endl;
        EC_KEY_free(pubkey);
        return -1;
    }
    int verify_status = ECDSA_do_verify(hash.data(), SHA256_DIGEST_LENGTH, sig, pubkey);
    ECDSA_SIG_free(sig);
    EC_KEY_free(pubkey);

    if (verify_status == 1) {
        return 0;
    } else {
        std::cerr << "Signature does not match: " << verify_status << std::endl;
        return -1;
    }
}

int sign_stm32_image(std::vector<unsigned char>& image, const char* private_key_desc, const char* public_key_desc, const char* passphrase, const char* output_hash_to_sign = nullptr, const char* input_signature = nullptr) {
    if (image.empty()) {
        std::cerr << "Image data is empty" << std::endl;
        return -1;
    }

    // Must have at least a public key
    if (!public_key_desc && !private_key_desc) {
        std::cerr << "Must specify either a public key or private key" << std::endl;
        return -1;
    }

    EC_KEY* public_key = nullptr;
    EC_KEY* private_key = nullptr;

    // Load public key if provided
    if (public_key_desc && std::strlen(public_key_desc) > 0) {
        if (load_public_key(public_key_desc, passphrase, &public_key) != 0) {
            std::cerr << "Failed to load public key" << std::endl;
            return -1;
        }
    }

    // Load private key if provided (only needed for signing)
    if (private_key_desc && std::strlen(private_key_desc) > 0) {
        if (load_private_key(private_key_desc, passphrase, &private_key) != 0) {
            std::cerr << "Failed to load private key" << std::endl;
            if (public_key) EC_KEY_free(public_key);
            return -1;
        }

        // If no separate public key was provided, extract public key from private key
        if (!public_key) {
            // Get the raw public key bytes using existing function
            std::vector<unsigned char> pubkey_bytes = get_raw_pubkey(private_key);
            if (pubkey_bytes.empty()) {
                std::cerr << "Failed to extract public key from private key" << std::endl;
                EC_KEY_free(private_key);
                return -1;
            }

            // Get the algorithm to determine the curve
            int algo = get_key_algorithm(private_key);
            if (algo < 0) {
                std::cerr << "Failed to get algorithm from private key" << std::endl;
                EC_KEY_free(private_key);
                return -1;
            }

            // Recreate the public key using the extracted bytes
            if (get_ec_pubkey(pubkey_bytes.data(), pubkey_bytes.size(), static_cast<uint32_t>(algo), &public_key) != 0) {
                std::cerr << "Failed to create public key from private key" << std::endl;
                EC_KEY_free(private_key);
                return -1;
            }
        }
    }

    if (!public_key) {
        std::cerr << "No valid key available" << std::endl;
        return -1;
    }

    STM32Header header = unpack_stm32_header(image);

    if (std::strncmp(header.magic, STM32_MAGIC, sizeof(header.magic)) != 0) {
        std::cerr << "Not an STM32 header (signature FAIL)" << std::endl;
        if (public_key) EC_KEY_free(public_key);
        if (private_key) EC_KEY_free(private_key);
        return -1;
    }

    // Ensure reserved fields are set to 0
    header.reserved1 = 0;
    header.reserved2 = 0;


    // Get the public key
    std::vector<unsigned char> pubkey = get_raw_pubkey(public_key);
    if (pubkey.empty()) {
        if (public_key) EC_KEY_free(public_key);
        if (private_key) EC_KEY_free(private_key);
        return -1;
    }
    print_hex("Public Key", pubkey);

    std::memcpy(header.ecdsa_pubkey, pubkey.data(), pubkey.size());
    if(get_key_algorithm(public_key) < 0) {
        if (public_key) EC_KEY_free(public_key);
        if (private_key) EC_KEY_free(private_key);
        return -1;
    }
    header.ecdsa_algo = static_cast<uint32_t>(get_key_algorithm(public_key));
    header.option_flags = 0;
    std::memset(header.padding, 0, sizeof(header.padding)); // Ensure padding is zeroed
    repack_stm32_header(image, header);

    // The ROM code hashes exactly 'header.length' bytes after the header (256 bytes), so we must not include trailing padding.
    size_t hash_end = sizeof(STM32Header) + header.length;
    if (hash_end > image.size()) {
        std::cerr << "Image too short: expected at least " << hash_end << " bytes, got " << image.size() << std::endl;
        if (public_key) EC_KEY_free(public_key);
        if (private_key) EC_KEY_free(private_key);
        return -1;
    }
    std::vector<unsigned char> buffer_to_hash(image.begin() + offsetof(STM32Header, hdr_version), image.begin() + static_cast<std::ptrdiff_t>(hash_end));

    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    if (!SHA256(buffer_to_hash.data(), buffer_to_hash.size(), hash.data())) {
        std::cerr << "Failed to compute SHA-256 hash" << std::endl;
        if (public_key) EC_KEY_free(public_key);
        if (private_key) EC_KEY_free(private_key);
        return -1;
    }
    print_hex("Hash(sha256)", hash);

    // Write hash to file only if output_hash_to_sign is specified
    if (output_hash_to_sign) {
        std::ofstream hash_file(output_hash_to_sign, std::ios::binary);
        if (hash_file) {
            hash_file.write(reinterpret_cast<const char*>(hash.data()), static_cast<std::streamsize>(hash.size()));
            hash_file.close();
            std::cout << "Hash written to: " << output_hash_to_sign << std::endl;
        } else {
            std::cerr << "Warning: Failed to write hash to " << output_hash_to_sign << std::endl;
        }

        // If we're only generating the hash, stop here
        if (!input_signature && !private_key) {
            std::cout << "Hash generation complete. No signature will be applied." << std::endl;
            // Clean up keys
            if (public_key) EC_KEY_free(public_key);
            if (private_key) EC_KEY_free(private_key);
            return 0;
        }
    }

    // Apply signature from file if provided
    if (input_signature) {
        std::ifstream sig_file(input_signature, std::ios::binary);
        if (!sig_file) {
            std::cerr << "Failed to open signature file: " << input_signature << std::endl;
            if (public_key) EC_KEY_free(public_key);
            if (private_key) EC_KEY_free(private_key);
            return -1;
        }

        std::vector<unsigned char> signature_data((std::istreambuf_iterator<char>(sig_file)), std::istreambuf_iterator<char>());
        sig_file.close();

        // Parse signature (handles both DER and raw formats)
        std::vector<unsigned char> signature = parse_der_signature(signature_data);
        if (signature.empty()) {
            std::cerr << "Failed to parse signature file" << std::endl;
            if (public_key) EC_KEY_free(public_key);
            if (private_key) EC_KEY_free(private_key);
            return -1;
        }

        if (signature.size() != sizeof(header.signature)) {
            std::cerr << "Invalid signature size after parsing: expected " << sizeof(header.signature)
                      << " bytes, got " << signature.size() << " bytes" << std::endl;
            if (public_key) EC_KEY_free(public_key);
            if (private_key) EC_KEY_free(private_key);
            return -1;
        }

        print_hex("External Signature", signature);
        std::memcpy(image.data() + offsetof(STM32Header, signature), signature.data(), signature.size());

        std::cout << "External signature applied from: " << input_signature << std::endl;
    }
    // Only sign with private key if available and no external signature provided
    else if (private_key) {
        ECDSA_SIG* sig = ECDSA_do_sign(hash.data(), SHA256_DIGEST_LENGTH, private_key);
        if (sig == nullptr) {
            std::cerr << "Failed to sign the image" << std::endl;
            if (public_key) EC_KEY_free(public_key);
            if (private_key) EC_KEY_free(private_key);
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
            if (public_key) EC_KEY_free(public_key);
            if (private_key) EC_KEY_free(private_key);
            return -1;
        }
        print_hex("ECC key(r)", r_bytes);
        print_hex("ECC key(s)", s_bytes);

        std::vector<unsigned char> signature(sizeof(header.signature));
        std::memset(signature.data(), 0, signature.size());
        std::memcpy(signature.data() + (sizeof(header.signature) / 2 - r_bytes.size()), r_bytes.data(), r_bytes.size());
        std::memcpy(signature.data() + sizeof(header.signature) - s_bytes.size(), s_bytes.data(), s_bytes.size());
        print_hex("Signature", signature);

        std::memcpy(image.data() + offsetof(STM32Header, signature), signature.data(), signature.size());
        ECDSA_SIG_free(sig);
    } else {
        std::cout << "No private key provided and no external signature - signature not generated (public key embedded only)" << std::endl;
    }

    // Save if we need to verify (before cleaning up keys)
    bool should_verify = (private_key != nullptr || input_signature != nullptr);

    // Clean up keys
    if (public_key) EC_KEY_free(public_key);
    if (private_key) EC_KEY_free(private_key);

    // Verify the signature only if it was signed
    if (should_verify) {
        return verify_stm32_image(image);
    }

    return 0;
}

void usage(const char* argv0) {
    std::cout << "Usage: " << argv0 << " [-k private_key] [-u public_key] [-p passphrase/pin] [-v] [-i input_file] [-o output_file] [-h hash_file] [-s output_hash_to_sign] [-d input_signature]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -k  Private key file or PKCS#11 URI (required for signing)" << std::endl;
    std::cout << "  -u  Public key file (required for public key hash and sha to sign generation)" << std::endl;
    std::cout << "  -p  Passphrase or PIN for private key" << std::endl;
    std::cout << "  -v  Verbose mode" << std::endl;
    std::cout << "  -i  Input image file" << std::endl;
    std::cout << "  -o  Output signed image file" << std::endl;
    std::cout << "  -h  Output file for public key hash" << std::endl;
    std::cout << "  -s  Output file for hash to sign" << std::endl;
    std::cout << "  -d  Input signature file (DER or raw format)" << std::endl;
    std::cout << std::endl;
    std::cout << "Two-step signing workflow:" << std::endl;
    std::cout << "  Step 1: Generate hash to sign" << std::endl;
    std::cout << "    " << argv0 << " -u public_key.pem -i input.stm32 -s hash.bin" << std::endl;
    std::cout << "  Step 2: Apply external signature" << std::endl;
    std::cout << "    " << argv0 << " -u public_key.pem -i input.stm32 -d signature.der -o output-signed.stm32" << std::endl;
}

int main(int argc, char* argv[]) {
    const char* private_key_desc = nullptr;
    const char* public_key_desc = nullptr;
    const char* passphrase = nullptr;
    const char* input_file = nullptr;
    const char* output_file = nullptr;
    const char* output_hash = nullptr;
    const char* output_hash_to_sign = nullptr;
    const char* input_signature = nullptr;

    int opt;
    if (argc == 1) {
        usage(argv[0]);
        return -1;
    }

    while ((opt = getopt(argc, argv, "k:u:p:h:s:d:vi:o:")) != -1) {
        switch (opt) {
            case 'k':
                private_key_desc = optarg;
                break;
            case 'u':
                public_key_desc = optarg;
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
            case 's':
                output_hash_to_sign = optarg;
                break;
            case 'd':
                input_signature = optarg;
                break;
            case 'i':
                input_file = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            default:
                usage(argv[0]);
                return -1;
        }
    }

    // Validate arguments
    if (input_file) {
        // When processing an input file, we need a public key (can come from private key or explicit public key)
        // AND either a private key for signing OR an external signature
        if (!private_key_desc && !public_key_desc) {
            std::cerr << "Error: Must specify either -k (private key) or -u (public key) when processing an image" << std::endl;
            return -1;
        }

        // If we have a public key but no private key, we need either -s (to generate hash) or -d (to apply signature)
        if (!private_key_desc && public_key_desc && !output_hash_to_sign && !input_signature) {
            std::cerr << "Error: When using only public key (-u), must specify either -s (generate hash) or -d (apply signature)" << std::endl;
            return -1;
        }
    }

    if (output_hash && !private_key_desc && !public_key_desc) {
        std::cerr << "Error: Must specify either -k (private key) or -u (public key) when generating public key hash (-h)" << std::endl;
        return -1;
    }

    if (input_signature && private_key_desc) {
        std::cerr << "Error: Cannot specify both -d (external signature) and -k (private key). Use one or the other." << std::endl;
        return -1;
    }

    if (input_file) {
        std::ifstream image_file(input_file, std::ios::binary);
        std::vector<unsigned char> image((std::istreambuf_iterator<char>(image_file)), std::istreambuf_iterator<char>());
        image_file.close();

        if (sign_stm32_image(image, private_key_desc, public_key_desc, passphrase, output_hash_to_sign, input_signature) != 0) {
            return -1;
        }

        if (output_file) {
            std::ofstream output(output_file, std::ios::binary);
            output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
            output.close();
        }
    }

    if (output_hash) {
        if (hash_pubkey(private_key_desc, public_key_desc, passphrase, output_hash) != 0) {
            return -1;
        }
    }

    if (engine) {
        ENGINE_finish(engine);
        ENGINE_free(engine);
    }

    // Securely erase the passphrase
    if (passphrase) {
        OPENSSL_cleanse(static_cast<void*>(const_cast<char*>(passphrase)), std::strlen(passphrase));
    }

    // Securely erase the key_desc in case it's a pkcs11 uri with pin
    if (private_key_desc) {
        OPENSSL_cleanse(static_cast<void*>(const_cast<char*>(private_key_desc)), std::strlen(private_key_desc));
    }

    return 0;
}
