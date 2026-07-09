// SPDX-License-Identifier: GPL-3.0-or-later

#include "stm32_image_format_internal.hpp"

#include "crypto_support.hpp"
#include "openssl_raii.hpp"

#include <cstring>
#include <iostream>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace {

/*******************************************************************
 * https://wiki.st.com/stm32mpu/wiki/STM32_header_for_binary_files *
 *                                                                 *
 * Notes (STM32MP15 / header v1):                                  *
 * - The signature is calculated over the data starting at offset  *
 *   0x48 (hdr_version field) up to the last byte given by the     *
 *   image_length field (i.e. sizeof(header) + header.length).     *
 * - The ecdsa_pubkey contains the public key (x, y) coordinates   *
 *   of the ECDSA key (64 bytes total).                            *
 *******************************************************************/

// STM32MP15x header (header v1)
struct STM32MP15Header {
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

STM32MP15Header unpack_stm32mp15_header(const std::vector<unsigned char>& image) {
    STM32MP15Header header;
    std::memcpy(&header, image.data(), sizeof(STM32MP15Header));
    return header;
}

void repack_stm32mp15_header(std::vector<unsigned char>& image, const STM32MP15Header& header) {
    std::memcpy(image.data(), &header, sizeof(STM32MP15Header));
}

class STM32MP15Format final : public STM32ImageFormat {
public:
    const char* description() const override {
        return "STM32MP15x header (v1)";
    }

    int sign(std::vector<unsigned char>& image, const char* key_desc, const char* passphrase) const override;
    int verify(const std::vector<unsigned char>& image) const override;
};

int STM32MP15Format::verify(const std::vector<unsigned char>& image) const {
    if (image.size() < sizeof(STM32MP15Header)) {
        std::cerr << "Image too short for an STM32MP15x header: got " << image.size() << " bytes" << std::endl;
        return -1;
    }
    STM32MP15Header header = unpack_stm32mp15_header(image);

    // The ROM code hashes exactly 'header.length' bytes after the header (256 bytes), so we must not include trailing padding.
    size_t hash_end = sizeof(STM32MP15Header) + header.length;
    if (hash_end > image.size()) {
        std::cerr << "Image too short: expected at least " << hash_end << " bytes, got " << image.size() << std::endl;
        return -1;
    }
    std::vector<unsigned char> buffer_to_hash(image.begin() + offsetof(STM32MP15Header, hdr_version), image.begin() + static_cast<std::ptrdiff_t>(hash_end));
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    if (!SHA256(buffer_to_hash.data(), buffer_to_hash.size(), hash.data())) {
        std::cerr << "Failed to compute SHA-256 hash" << std::endl;
        return -1;
    }
    std::vector<unsigned char> signature(header.signature, header.signature + sizeof(header.signature));
    print_hex("Hash", hash);
    print_hex("Signature", signature);

    EcdsaSigPtr sig(ECDSA_SIG_new());

    if (!sig) {
        std::cerr << "Failed to create ECDSA_SIG structure" << std::endl;
        return -1;
    }

    // Extract r and s from the signature buffer
    BignumPtr r(BN_bin2bn(signature.data(), sizeof(header.signature) / 2, nullptr));
    BignumPtr s(BN_bin2bn(signature.data() + sizeof(header.signature) / 2, sizeof(header.signature) / 2, nullptr));
    if (!r || !s) {
        std::cerr << "Failed to create BIGNUMs for r and s" << std::endl;
        return -1;
    }

    if (ECDSA_SIG_set0(sig.get(), r.get(), s.get()) == 0) {
        std::cerr << "Failed to set r and s in ECDSA_SIG" << std::endl;
        return -1;
    }
    r.release();
    s.release();

    // EVP_DigestVerify expects a DER-encoded ECDSA signature.
    unsigned char* raw_der = nullptr;
    int der_len = i2d_ECDSA_SIG(sig.get(), &raw_der);
    OpenSslBufferPtr der(raw_der);
    if (der_len <= 0) {
        std::cerr << "Failed to DER-encode signature" << std::endl;
        return -1;
    }

    EVP_PKEY* raw_pubkey = nullptr;
    if (get_ec_pubkey(header.ecdsa_pubkey, sizeof(header.ecdsa_pubkey), header.ecdsa_algo, &raw_pubkey) != 0) {
        std::cerr << "Failed to get EVP_PKEY from public key" << std::endl;
        return -1;
    }
    EvpPkeyPtr pubkey(raw_pubkey);

    EvpMdCtxPtr md_ctx(EVP_MD_CTX_new());
    int verify_status = -1;
    if (md_ctx &&
        EVP_DigestVerifyInit(md_ctx.get(), nullptr, EVP_sha256(), nullptr, pubkey.get()) == 1) {
        verify_status = EVP_DigestVerify(md_ctx.get(), der.get(), static_cast<size_t>(der_len),
                                         buffer_to_hash.data(), buffer_to_hash.size());
    }

    if (verify_status == 1) {
        return 0;
    } else {
        std::cerr << "Signature does not match: " << verify_status << std::endl;
        return -1;
    }
}

int STM32MP15Format::sign(std::vector<unsigned char>& image, const char* key_desc, const char* passphrase) const {
    if (image.size() < sizeof(STM32MP15Header)) {
        std::cerr << "Image too short for an STM32MP15x header: got " << image.size() << " bytes" << std::endl;
        return -1;
    }
    EVP_PKEY* raw_key = nullptr;
    if (load_key(key_desc, passphrase, &raw_key) != 0) {
        std::cerr << "Failed to load key: " << key_desc << std::endl;
        return -1;
    }
    EvpPkeyPtr key(raw_key);

    STM32MP15Header header = unpack_stm32mp15_header(image);

    // Ensure reserved fields are set to 0
    header.reserved1 = 0;
    header.reserved2 = 0;


    // Get the public key from the private key
    std::vector<unsigned char> pubkey = get_raw_pubkey(key.get());
    if (pubkey.empty()) {
        return -1;
    }
    print_hex("Public Key", pubkey);

    std::memcpy(header.ecdsa_pubkey, pubkey.data(), pubkey.size());
    int algo = get_key_algorithm(key.get());
    if (algo < 0) {
        return -1;
    }
    header.ecdsa_algo = static_cast<uint32_t>(algo);
    header.option_flags = 0;
    std::memset(header.padding, 0, sizeof(header.padding)); // Ensure padding is zeroed
    repack_stm32mp15_header(image, header);

    // The ROM code hashes exactly 'header.length' bytes after the header (256 bytes), so we must not include trailing padding.
    size_t hash_end = sizeof(STM32MP15Header) + header.length;
    if (hash_end > image.size()) {
        std::cerr << "Image too short: expected at least " << hash_end << " bytes, got " << image.size() << std::endl;
        return -1;
    }
    std::vector<unsigned char> buffer_to_hash(image.begin() + offsetof(STM32MP15Header, hdr_version), image.begin() + static_cast<std::ptrdiff_t>(hash_end));

    // Sign with the high-level EVP interface so that provider-backed keys
    // (e.g. non-extractable PKCS#11 keys) sign in-place. This produces a
    // DER-encoded ECDSA signature.
    EvpMdCtxPtr md_ctx(EVP_MD_CTX_new());
    std::vector<unsigned char> der;
    size_t der_len = 0;
    if (!md_ctx ||
        EVP_DigestSignInit(md_ctx.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1 ||
        EVP_DigestSign(md_ctx.get(), nullptr, &der_len, buffer_to_hash.data(), buffer_to_hash.size()) != 1) {
        std::cerr << "Failed to initialize signing" << std::endl;
        return -1;
    }
    der.resize(der_len);
    if (EVP_DigestSign(md_ctx.get(), der.data(), &der_len, buffer_to_hash.data(), buffer_to_hash.size()) != 1) {
        std::cerr << "Failed to sign the image" << std::endl;
        return -1;
    }
    der.resize(der_len);

    // Decode the DER signature back to (r, s) to build the fixed-size raw
    // signature expected in the STM32 header.
    const unsigned char* der_ptr = der.data();
    EcdsaSigPtr sig(d2i_ECDSA_SIG(nullptr, &der_ptr, static_cast<long>(der_len)));
    if (sig == nullptr) {
        std::cerr << "Failed to decode ECDSA signature" << std::endl;
        return -1;
    }

    const BIGNUM* r;
    const BIGNUM* s;
    ECDSA_SIG_get0(sig.get(), &r, &s);

    std::vector<unsigned char> r_bytes(static_cast<size_t>(BN_num_bytes(r)));
    std::vector<unsigned char> s_bytes(static_cast<size_t>(BN_num_bytes(s)));
    if (BN_bn2binpad(r, r_bytes.data(), static_cast<int>(r_bytes.size())) < 0 || BN_bn2binpad(s, s_bytes.data(), static_cast<int>(s_bytes.size())) < 0) {
        std::cerr << "Failed to convert BIGNUM to binary" << std::endl;
        return -1;
    }
    print_hex("ECC key(r)", r_bytes);
    print_hex("ECC key(s)", s_bytes);

    std::vector<unsigned char> signature(sizeof(header.signature));
    std::memset(signature.data(), 0, signature.size());
    std::memcpy(signature.data() + (sizeof(header.signature) / 2 - r_bytes.size()), r_bytes.data(), r_bytes.size());
    std::memcpy(signature.data() + sizeof(header.signature) - s_bytes.size(), s_bytes.data(), s_bytes.size());
    print_hex("Signature", signature);

    std::memcpy(image.data() + offsetof(STM32MP15Header, signature), signature.data(), signature.size());

    // Verify the signature
    return verify(image);

}

} // namespace

const STM32ImageFormat* get_stm32mp15_format() {
    static const STM32MP15Format mp15_format;
    return &mp15_format;
}
