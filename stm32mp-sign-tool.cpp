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

static bool verbose = false;
static ENGINE* engine = nullptr;

/*******************************************************************/
/* STM32 header format (STM32MP15x)                                */
/* https://wiki.st.com/stm32mpu/wiki/STM32_header_for_binary_files */
/*                                                                 */
/*******************************************************************/
#define STM32_MAGIC "STM2" // 0x53544D32
#define HDR_VERSION  0x00010000 // Header version v1.0 

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

std::vector<unsigned char> get_raw_pubkey(EC_KEY* key) {
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

STM32Header unpack_stm32_header(const std::vector<unsigned char>& image) {
    STM32Header header;
    std::memcpy(&header, image.data(), sizeof(STM32Header));
    return header;
}

void repack_stm32_header(std::vector<unsigned char>& image, const STM32Header& header) {
    std::memcpy(image.data(), &header, sizeof(STM32Header));
}

int key_algorithm(EC_KEY* key) {
    const EC_GROUP* group = EC_KEY_get0_group(key);
    int nid = EC_GROUP_get_curve_name(group);
    if (nid == NID_X9_62_prime256v1) {
        return 1;
    }
    else if (nid == NID_brainpoolP256r1) {
        return 2;
    }
    std::cerr << "Unsupported ECDSA curve" << std::endl;
    return -1;
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

int load_key(const char* key_desc, const char* passphrase, EC_KEY** ec_key) {
    *ec_key = nullptr;
    if (!key_desc || !ec_key) {
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

        *ec_key = PEM_read_ECPrivateKey(key_fp, nullptr, nullptr, (void*)passphrase);
        fclose(key_fp);
        if (!*ec_key) {
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
    EC_KEY* key = nullptr;
    if (load_key(key_desc, passphrase, &key) != 0) {
        std::cerr << "Failed to load key" << std::endl;
        return -1;
    }
    if (!key) {
        std::cerr << "Invalid key" << std::endl;
        return -1;
    }
    std::vector<unsigned char> pubkey = get_raw_pubkey(const_cast<EC_KEY*>(key));
    if (pubkey.empty()) {
        std::cerr << "Failed to get raw public key" << std::endl;
        return -1;
    }

    std::vector<unsigned char> phash(SHA256_DIGEST_LENGTH);
    SHA256(pubkey.data(), pubkey.size(), phash.data());
    print_hex("Pubkey(sha256)", phash);

    std::ofstream output(output_file, std::ios::binary);
    output.write(reinterpret_cast<const char*>(phash.data()), static_cast<std::streamsize>(phash.size()));
    output.close();

    return 0;
 
}

int verify_stm32_image(const std::vector<unsigned char>& image, const char* key_desc, const char* passphrase) {
    if (image.empty()) {
        std::cerr << "Image data is empty" << std::endl;
        return -1;
    }
    if (!key_desc || std::strlen(key_desc) == 0) {
        std::cerr << "Key file path is empty" << std::endl;
        return -1;
    }
    EC_KEY* key = nullptr;
    if (load_key(key_desc, passphrase, &key) != 0) {
        std::cerr << "Failed to load key" << std::endl;
        return 1;
    }

    STM32Header header = unpack_stm32_header(image);

    if (std::strncmp(header.magic, STM32_MAGIC, sizeof(header.magic)) != 0) {
        std::cerr << "Not an STM32 header (signature FAIL)" << std::endl;
        EC_KEY_free(key);
        return -1;
    }

    std::vector<unsigned char> pubkey = get_raw_pubkey(key);
    if (pubkey.empty()) {
        EC_KEY_free(key);
        return -1;
    }
    print_hex("Public Key", pubkey);

    if (std::memcmp(header.ecdsa_pubkey, pubkey.data(), pubkey.size()) != 0) {
        std::cerr << "Image is not signed with the provided key" << std::endl;
        EC_KEY_free(key);
        return 1;
    }

    std::vector<unsigned char> buffer_to_hash(image.begin() + sizeof(STM32Header), image.end());
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    if (!SHA256(buffer_to_hash.data(), buffer_to_hash.size(), hash.data())) {
        std::cerr << "Failed to compute SHA-256 hash" << std::endl;
        EC_KEY_free(key);
        return -1;
    }
    std::vector<unsigned char> signature(header.signature, header.signature + sizeof(header.signature));
    print_hex("Hash", hash);
    print_hex("Signature", signature);

    // Extract the signature from the header
    const unsigned char* sig_ptr = header.signature;
    ECDSA_SIG* sig = ECDSA_SIG_new();

    if (!sig) {
        std::cerr << "Failed to create ECDSA_SIG structure" << std::endl;
        EC_KEY_free(key);
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
        EC_KEY_free(key);
        return -1;
    }

    if (ECDSA_SIG_set0(sig, r, s) == 0) {
        BN_free(r);
        BN_free(s);
        std::cerr << "Failed to set r and s in ECDSA_SIG" << std::endl;
        ECDSA_SIG_free(sig);
        EC_KEY_free(key);
        return -1;
    }

    int verify_status = ECDSA_do_verify(hash.data(), SHA256_DIGEST_LENGTH, sig, key);
    ECDSA_SIG_free(sig);
    EC_KEY_free(key);

    if (verify_status == 1) {
        return 0;
    } else {
        std::cerr << "Signature does not match: " << verify_status << std::endl;
        return -1;
    }
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
    EC_KEY* key = nullptr;
    if (load_key(key_desc, passphrase, &key) != 0) {
        std::cerr << "Failed to load key" << std::endl;
        return -1;
    }

    STM32Header header = unpack_stm32_header(image);

    if (std::strncmp(header.magic, STM32_MAGIC, sizeof(header.magic)) != 0) {
        std::cerr << "Not an STM32 header (signature FAIL)" << std::endl;
        EC_KEY_free(key);
        return -1;
    }

    // Ensure reserved fields are set to 0
    header.reserved1 = 0;
    header.reserved2 = 0;

    // Set header version
    header.hdr_version = HDR_VERSION;

    // Get the public key from the private key
    std::vector<unsigned char> pubkey = get_raw_pubkey(key);
    if (pubkey.empty()) {
        EC_KEY_free(key);
        return -1;
    }
    print_hex("Public Key", pubkey);

    std::memcpy(header.ecdsa_pubkey, pubkey.data(), pubkey.size());
    header.ecdsa_algo = static_cast<uint32_t>(key_algorithm(key));
    if (header.ecdsa_algo < 0) {
        EC_KEY_free(key);
        return -1;
    }
    header.option_flags = 0;
    std::memset(header.padding, 0, sizeof(header.padding)); // Ensure padding is zeroed
    header.binary_type = 0x10; // 0x10-0x1F: FSBL
    repack_stm32_header(image, header);

    // Ensure the buffer to hash is correctly constructed
    std::vector<unsigned char> buffer_to_hash(image.begin() + sizeof(STM32Header), image.end());

    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    if (!SHA256(buffer_to_hash.data(), buffer_to_hash.size(), hash.data())) {
        std::cerr << "Failed to compute SHA-256 hash" << std::endl;
        EC_KEY_free(key);
        return -1;
    }
    print_hex("Hash(sha256)", hash);

    ECDSA_SIG* sig = ECDSA_do_sign(hash.data(), SHA256_DIGEST_LENGTH, key);
    if (sig == nullptr) {
        std::cerr << "Failed to sign the image" << std::endl;
        EC_KEY_free(key);
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
        EC_KEY_free(key);
        return -1;
    }
    print_hex("ECC key(r)", r_bytes);
    print_hex("ECC key(s)", s_bytes);

    std::vector<unsigned char> signature(r_bytes.size() + s_bytes.size());
    std::memcpy(signature.data(), r_bytes.data(), r_bytes.size());
    std::memcpy(signature.data() + r_bytes.size(), s_bytes.data(), s_bytes.size());
    print_hex("Signature", signature);

    std::memcpy(image.data() + offsetof(STM32Header, signature), signature.data(), signature.size());
    ECDSA_SIG_free(sig);
    EC_KEY_free(key);

    // Verify the signature
    if (verify_stm32_image(image, key_desc, passphrase)) {
        return -1;
    }

    return 0;
}

void usage(const char* argv0) {
    std::cerr << "Usage: " << argv0 << " -k key_desc [-p passphrase/pin] [-v] [-i input_file] [-o output_file]" << std::endl;
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

    while ((opt = getopt(argc, argv, "k:p:h:vi:o:")) != -1) {
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

    if(output_hash) {
        if (hash_pubkey(key_desc, passphrase, output_hash) != 0) {
            return -1;
        }
    }

    if (engine) {
        ENGINE_finish(engine);
        ENGINE_free(engine);
    }

    // Securely erase the passphrase
    if (passphrase) {
        std::memset((void*)passphrase, 0, std::strlen(passphrase));
    }

    return 0;
}
