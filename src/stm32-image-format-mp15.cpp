// SPDX-License-Identifier: GPL-3.0-or-later

#include "stm32-image-format-mp15.hpp"

#include "openssl-support.hpp"
#include "utils.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <openssl/sha.h>
#include <stdexcept>
#include <utility>

STM32ImageFormatMP15::STM32ImageFormatMP15(std::shared_ptr<OpenSSLSupport> openSslSupport, std::shared_ptr<Utils> utils)
    : openSslSupport(std::move(openSslSupport)),
      utils(std::move(utils)) {
    if (!this->openSslSupport) {
        throw std::invalid_argument("OpenSSLSupport must not be null");
    }
    if (!this->utils) {
        throw std::invalid_argument("Utils must not be null");
    }
}

STM32ImageFormatMP15::STM32HeaderV1 STM32ImageFormatMP15::unpackHeader(const std::vector<unsigned char>& image) {
    STM32HeaderV1 header;
    std::memcpy(&header, image.data(), sizeof(STM32HeaderV1));
    return header;
}

void STM32ImageFormatMP15::repackHeader(std::vector<unsigned char>& image, const STM32HeaderV1& header) {
    std::memcpy(image.data(), &header, sizeof(STM32HeaderV1));
}

int STM32ImageFormatMP15::verify(const std::vector<unsigned char>& image) {
    if (image.size() < sizeof(STM32HeaderV1)) {
        std::cerr << "Image too short for an STM32 v1 header: got " << image.size() << " bytes" << std::endl;
        return -1;
    }
    STM32HeaderV1 header = unpackHeader(image);

    size_t hashEnd = sizeof(STM32HeaderV1) + header.length;
    if (hashEnd > image.size()) {
        std::cerr << "Image too short: expected at least " << hashEnd << " bytes, got " << image.size() << std::endl;
        return -1;
    }
    std::vector<unsigned char> bufferToHash(image.begin() + offsetof(STM32HeaderV1, hdr_version), image.begin() + static_cast<std::ptrdiff_t>(hashEnd));
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    if (!SHA256(bufferToHash.data(), bufferToHash.size(), hash.data())) {
        std::cerr << "Failed to compute SHA-256 hash" << std::endl;
        return -1;
    }
    std::vector<unsigned char> signature(header.signature, header.signature + sizeof(header.signature));
    utils->printHex("Hash", hash);
    utils->printHex("Signature", signature);

    EcdsaSigPtr sig(ECDSA_SIG_new());

    if (!sig) {
        std::cerr << "Failed to create ECDSA_SIG structure" << std::endl;
        return -1;
    }

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

    unsigned char* rawDer = nullptr;
    int derLen = i2d_ECDSA_SIG(sig.get(), &rawDer);
    OpenSslBufferPtr der(rawDer);
    if (derLen <= 0) {
        std::cerr << "Failed to DER-encode signature" << std::endl;
        return -1;
    }

    EVP_PKEY* rawPubkey = nullptr;
    if (openSslSupport->getEcPubkey(header.ecdsa_pubkey, sizeof(header.ecdsa_pubkey), header.ecdsa_algo, &rawPubkey) != 0) {
        std::cerr << "Failed to get EVP_PKEY from public key" << std::endl;
        return -1;
    }
    EvpPkeyPtr pubkey(rawPubkey);

    EvpMdCtxPtr mdCtx(EVP_MD_CTX_new());
    int verifyStatus = -1;
    if (mdCtx &&
        EVP_DigestVerifyInit(mdCtx.get(), nullptr, EVP_sha256(), nullptr, pubkey.get()) == 1) {
        verifyStatus = EVP_DigestVerify(mdCtx.get(), der.get(), static_cast<size_t>(derLen),
                                        bufferToHash.data(), bufferToHash.size());
    }

    if (verifyStatus == 1) {
        return 0;
    } else {
        std::cerr << "Signature does not match: " << verifyStatus << std::endl;
        return -1;
    }
}

int STM32ImageFormatMP15::sign(std::vector<unsigned char>& image, const std::string& keyDesc, const std::string& passphrase) {
    if (image.size() < sizeof(STM32HeaderV1)) {
        std::cerr << "Image too short for an STM32 v1 header: got " << image.size() << " bytes" << std::endl;
        return -1;
    }
    EVP_PKEY* rawKey = nullptr;
    if (openSslSupport->loadKey(keyDesc, passphrase, &rawKey) != 0) {
        std::cerr << "Failed to load key: " << keyDesc << std::endl;
        return -1;
    }
    EvpPkeyPtr key(rawKey);

    STM32HeaderV1 header = unpackHeader(image);

    header.reserved1 = 0;
    header.reserved2 = 0;

    std::vector<unsigned char> pubkey = openSslSupport->getRawPubkey(key.get());
    if (pubkey.empty()) {
        return -1;
    }
    utils->printHex("Public Key", pubkey);

    std::memcpy(header.ecdsa_pubkey, pubkey.data(), pubkey.size());
    int algo = openSslSupport->getKeyAlgorithm(key.get());
    if (algo < 0) {
        return -1;
    }
    header.ecdsa_algo = static_cast<uint32_t>(algo);
    header.option_flags = 0;
    std::memset(header.padding, 0, sizeof(header.padding));
    repackHeader(image, header);

    size_t hashEnd = sizeof(STM32HeaderV1) + header.length;
    if (hashEnd > image.size()) {
        std::cerr << "Image too short: expected at least " << hashEnd << " bytes, got " << image.size() << std::endl;
        return -1;
    }
    std::vector<unsigned char> bufferToHash(image.begin() + offsetof(STM32HeaderV1, hdr_version), image.begin() + static_cast<std::ptrdiff_t>(hashEnd));

    EvpMdCtxPtr mdCtx(EVP_MD_CTX_new());
    std::vector<unsigned char> der;
    size_t derLen = 0;
    if (!mdCtx ||
        EVP_DigestSignInit(mdCtx.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1 ||
        EVP_DigestSign(mdCtx.get(), nullptr, &derLen, bufferToHash.data(), bufferToHash.size()) != 1) {
        std::cerr << "Failed to initialize signing" << std::endl;
        return -1;
    }
    der.resize(derLen);
    if (EVP_DigestSign(mdCtx.get(), der.data(), &derLen, bufferToHash.data(), bufferToHash.size()) != 1) {
        std::cerr << "Failed to sign the image" << std::endl;
        return -1;
    }
    der.resize(derLen);

    const unsigned char* derPtr = der.data();
    EcdsaSigPtr sig(d2i_ECDSA_SIG(nullptr, &derPtr, static_cast<long>(derLen)));
    if (sig == nullptr) {
        std::cerr << "Failed to decode ECDSA signature" << std::endl;
        return -1;
    }

    const BIGNUM* r;
    const BIGNUM* s;
    ECDSA_SIG_get0(sig.get(), &r, &s);

    std::vector<unsigned char> rBytes(static_cast<size_t>(BN_num_bytes(r)));
    std::vector<unsigned char> sBytes(static_cast<size_t>(BN_num_bytes(s)));
    if (BN_bn2binpad(r, rBytes.data(), static_cast<int>(rBytes.size())) < 0 || BN_bn2binpad(s, sBytes.data(), static_cast<int>(sBytes.size())) < 0) {
        std::cerr << "Failed to convert BIGNUM to binary" << std::endl;
        return -1;
    }
    utils->printHex("ECC key(r)", rBytes);
    utils->printHex("ECC key(s)", sBytes);

    std::vector<unsigned char> signature(sizeof(header.signature));
    std::memset(signature.data(), 0, signature.size());
    std::memcpy(signature.data() + (sizeof(header.signature) / 2 - rBytes.size()), rBytes.data(), rBytes.size());
    std::memcpy(signature.data() + sizeof(header.signature) - sBytes.size(), sBytes.data(), sBytes.size());
    utils->printHex("Signature", signature);

    std::memcpy(image.data() + offsetof(STM32HeaderV1, signature), signature.data(), signature.size());

    return verify(image);

}
