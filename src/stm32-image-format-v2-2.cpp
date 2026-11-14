// SPDX-License-Identifier: GPL-3.0-or-later

#include "stm32-image-format-v2-2.hpp"

#include "logger.hpp"
#include "openssl-keys.hpp"

#include <array>
#include <cassert>
#include <cstring>
#include <iostream>
#include <openssl/sha.h>
#include <stdexcept>
#include <utility>

STM32ImageFormatV2_2::STM32ImageFormatV2_2(
    std::shared_ptr<OpenSslKeys> openSslKeys,
    std::shared_ptr<Logger> logger,
    std::vector<std::string> publicKeyDescriptors,
    int publicKeyIndex)
    : openSslKeys(std::move(openSslKeys)),
      logger(std::move(logger)),
      publicKeyDescriptors(std::move(publicKeyDescriptors)),
      publicKeyIndex(publicKeyIndex) {
    if (!this->openSslKeys) {
        throw std::invalid_argument("OpenSslKeys must not be null");
    }
    if (!this->logger) {
        throw std::invalid_argument("Logger must not be null");
    }
}

STM32ImageFormatV2_2::STM32HeaderV2_2
STM32ImageFormatV2_2::unpackHeader(const std::vector<unsigned char>& image) {
    assert(image.size() >= HEADER_SIZE);
    STM32HeaderV2_2 header{};
    size_t offset = 0;

    std::memcpy(&header.base_header, image.data() + offset, sizeof(header.base_header));
    offset += sizeof(header.base_header);

    if ((header.base_header.option_flags & (1U << 0U)) != 0) {
        STM32AuthenticationExtensionV2_2 authenticationExtension{};
        std::memcpy(&authenticationExtension,
                    image.data() + offset,
                    sizeof(authenticationExtension));
        header.authentication_extension = authenticationExtension;
        offset += sizeof(authenticationExtension);
    }

    if ((header.base_header.option_flags & (1U << 1U)) != 0) {
        STM32DecryptionExtensionV2_2 decryptionExtension{};
        std::memcpy(&decryptionExtension,
                    image.data() + offset,
                    sizeof(decryptionExtension));
        header.decryption_extension = decryptionExtension;
        offset += sizeof(decryptionExtension);
    }

    std::memcpy(&header.padding_extension.header,
                image.data() + offset,
                sizeof(header.padding_extension.header));

    return header;
}

void STM32ImageFormatV2_2::repackHeader(std::vector<unsigned char>& image,
                                        const STM32HeaderV2_2& header) {
    size_t offset = 0;

    STM32BaseHeaderV2_2 baseHeader = header.base_header;
    baseHeader.option_flags |= 1U << 31U;
    baseHeader.extensions_length = static_cast<uint32_t>(HEADER_SIZE - sizeof(baseHeader));
    std::memcpy(image.data() + offset, &baseHeader, sizeof(baseHeader));
    offset += sizeof(baseHeader);

    if (header.authentication_extension) {
        std::memcpy(image.data() + offset,
                    &header.authentication_extension.value(),
                    sizeof(header.authentication_extension.value()));
        offset += sizeof(header.authentication_extension.value());
    }

    if (header.decryption_extension) {
        std::memcpy(image.data() + offset,
                    &header.decryption_extension.value(),
                    sizeof(header.decryption_extension.value()));
        offset += sizeof(header.decryption_extension.value());
    }

    STM32PaddingExtensionHeaderV2_2 paddingHeader{};
    const unsigned char paddingExtensionType[4] = {'S', 'T', 0xff, 0xff};
    std::memcpy(&paddingHeader.extension_type,
                paddingExtensionType,
                sizeof(paddingExtensionType));
    paddingHeader.extension_length = static_cast<uint32_t>(HEADER_SIZE - offset);
    std::memcpy(image.data() + offset, &paddingHeader, sizeof(paddingHeader));
    offset += sizeof(paddingHeader);

    std::memset(image.data() + offset, 0, HEADER_SIZE - offset);
}

std::vector<unsigned char> STM32ImageFormatV2_2::getSignedData(
    const std::vector<unsigned char>& image, size_t hashEnd) {
    // ST v2.2 excludes the last eight base-header padding bytes from the signature.
    constexpr size_t signedHeaderEnd = sizeof(STM32BaseHeaderV2_2) - 8;
    std::vector<unsigned char> data(
        image.begin() + offsetof(STM32BaseHeaderV2_2, hdr_version),
        image.begin() + signedHeaderEnd);
    data.insert(data.end(), image.begin() + sizeof(STM32BaseHeaderV2_2),
                image.begin() + static_cast<std::ptrdiff_t>(hashEnd));
    return data;
}

int STM32ImageFormatV2_2::verify(const std::vector<unsigned char>& image) {
    if (image.size() < HEADER_SIZE) {
        std::cerr << "Image too short for an STM32 v2.2 header: got " << image.size()
                  << " bytes" << std::endl;
        return -1;
    }
    STM32HeaderV2_2 header = unpackHeader(image);

    if (!header.authentication_extension) {
        std::cerr << "STM32 v2.2 image does not contain an authentication extension"
                  << std::endl;
        return -1;
    }
    if ((header.base_header.option_flags & (1U << 31U)) == 0) {
        std::cerr << "STM32 v2.2 image does not have header padding enabled"
                  << std::endl;
        return -1;
    }

    const STM32AuthenticationExtensionV2_2& authenticationExtension =
        header.authentication_extension.value();

    const unsigned char authenticationExtensionType[4] = {'S', 'T', 0x00, 0x02};
    if (std::memcmp(&authenticationExtension.extension_type,
                    authenticationExtensionType,
                    sizeof(authenticationExtensionType))
        != 0) {
        std::cerr << "Invalid authentication extension type" << std::endl;
        return -1;
    }
    if (authenticationExtension.extension_length != sizeof(authenticationExtension)) {
        std::cerr << "Invalid authentication extension length: "
                  << authenticationExtension.extension_length << std::endl;
        return -1;
    }

    if (authenticationExtension.public_key_count != PUBLIC_KEY_COUNT) {
        std::cerr << "Invalid public key count: "
                  << authenticationExtension.public_key_count << std::endl;
        return -1;
    }
    if (authenticationExtension.public_key_index >= PUBLIC_KEY_COUNT) {
        std::cerr << "Invalid public key index: "
                  << authenticationExtension.public_key_index << std::endl;
        return -1;
    }

    if (OpenSslKeys::validatePublicKeyHashes(
            reinterpret_cast<const unsigned char*>(authenticationExtension.public_key_hashes),
            PUBLIC_KEY_COUNT) != 0) {
        return -1;
    }

    if (header.decryption_extension) {
        const STM32DecryptionExtensionV2_2& decryptionExtension =
            header.decryption_extension.value();
        const unsigned char decryptionExtensionType[4] = {'S', 'T', 0x00, 0x01};
        if (std::memcmp(&decryptionExtension.extension_type,
                        decryptionExtensionType,
                        sizeof(decryptionExtensionType))
            != 0) {
            std::cerr << "Invalid decryption extension type" << std::endl;
            return -1;
        }
        if (decryptionExtension.extension_length != sizeof(decryptionExtension)) {
            std::cerr << "Invalid decryption extension length: "
                      << decryptionExtension.extension_length << std::endl;
            return -1;
        }
        if (decryptionExtension.key_size != 128U) {
            std::cerr << "Invalid decryption key size: " << decryptionExtension.key_size
                      << std::endl;
            return -1;
        }
    }

    const STM32PaddingExtensionHeaderV2_2& paddingExtension =
        header.padding_extension.header;
    const unsigned char paddingExtensionType[4] = {'S', 'T', 0xff, 0xff};
    if (std::memcmp(&paddingExtension.extension_type,
                    paddingExtensionType,
                    sizeof(paddingExtensionType))
        != 0) {
        std::cerr << "Invalid padding extension type" << std::endl;
        return -1;
    }

    size_t expectedPaddingLength =
        HEADER_SIZE - sizeof(header.base_header) - sizeof(authenticationExtension);
    if (header.decryption_extension) {
        expectedPaddingLength -= sizeof(header.decryption_extension.value());
    }
    if (paddingExtension.extension_length
        != static_cast<uint32_t>(expectedPaddingLength)) {
        std::cerr << "Invalid padding extension length: "
                  << paddingExtension.extension_length << std::endl;
        return -1;
    }

    const size_t expectedExtensionsLength = HEADER_SIZE - sizeof(header.base_header);
    if (header.base_header.extensions_length
        != static_cast<uint32_t>(expectedExtensionsLength)) {
        std::cerr << "Invalid header extensions length: "
                  << header.base_header.extensions_length << std::endl;
        return -1;
    }

    size_t hashEnd = HEADER_SIZE + header.base_header.length;
    if (hashEnd > image.size()) {
        std::cerr << "Image too short: expected at least " << hashEnd << " bytes, got "
                  << image.size() << std::endl;
        return -1;
    }
    if (image.size() > hashEnd) {
        std::cerr << "Warning: " << image.size() - hashEnd
                  << " trailing bytes beyond the declared payload are not authenticated."
                  << std::endl;
    }
    std::vector<unsigned char> bufferToHash = getSignedData(image, hashEnd);
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    if (!SHA256(bufferToHash.data(), bufferToHash.size(), hash.data())) {
        std::cerr << "Failed to compute SHA-256 hash" << std::endl;
        return -1;
    }
    std::vector<unsigned char> signature(
        header.base_header.signature,
        header.base_header.signature + sizeof(header.base_header.signature));
    logger->printHex("Hash", hash);
    logger->printHex("Signature", signature);

    std::array<unsigned char, SHA256_DIGEST_LENGTH> publicKeyHash{};
    if (!OpenSslKeys::computePublicKeyHash(authenticationExtension.ecdsa_public_key,
                                         sizeof(authenticationExtension.ecdsa_public_key),
                                         authenticationExtension.ecdsa_algorithm,
                                         publicKeyHash.data())) {
        std::cerr << "Failed to hash the selected public key" << std::endl;
        return -1;
    }

    const size_t publicKeyIndex =
        static_cast<size_t>(authenticationExtension.public_key_index);
    if (std::memcmp(publicKeyHash.data(),
                    authenticationExtension.public_key_hashes[publicKeyIndex],
                    publicKeyHash.size()) != 0) {
        std::cerr << "Selected public key does not match its public key hash"
                  << std::endl;
        return -1;
    }

    EcdsaSigPtr sig(ECDSA_SIG_new());
    if (!sig) {
        std::cerr << "Failed to create ECDSA_SIG structure" << std::endl;
        return -1;
    }

    BignumPtr r(BN_bin2bn(signature.data(),
                          sizeof(header.base_header.signature) / 2,
                          nullptr));
    BignumPtr s(BN_bin2bn(
        signature.data() + sizeof(header.base_header.signature) / 2,
        sizeof(header.base_header.signature) / 2,
        nullptr));
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
    if (openSslKeys->getEcPubkey(authenticationExtension.ecdsa_public_key,
                                 sizeof(authenticationExtension.ecdsa_public_key),
                                 authenticationExtension.ecdsa_algorithm,
                                 &rawPubkey)
        != 0) {
        std::cerr << "Failed to get EVP_PKEY from public key" << std::endl;
        return -1;
    }
    EvpPkeyPtr pubkey(rawPubkey);

    EvpMdCtxPtr mdCtx(EVP_MD_CTX_new());
    int verifyStatus = -1;
    if (mdCtx
        && EVP_DigestVerifyInit(mdCtx.get(), nullptr, EVP_sha256(), nullptr, pubkey.get())
               == 1) {
        verifyStatus = EVP_DigestVerify(mdCtx.get(),
                                        der.get(),
                                        static_cast<size_t>(derLen),
                                        bufferToHash.data(),
                                        bufferToHash.size());
    }

    if (verifyStatus == 1) {
        return 0;
    }

    std::cerr << "Signature does not match: " << verifyStatus << std::endl;
    return -1;
}

int STM32ImageFormatV2_2::sign(
    std::vector<unsigned char>& image,
    const std::string& keyDesc,
    const std::optional<std::string>& passphrase) {
    if (image.size() < HEADER_SIZE) {
        std::cerr << "Image too short for an STM32 v2.2 header: got " << image.size()
                  << " bytes" << std::endl;
        return -1;
    }
    if (publicKeyDescriptors.size() != PUBLIC_KEY_COUNT) {
        std::cerr << "STM32 header v2.2 requires exactly eight public keys (-K)" << std::endl;
        return -1;
    }
    if (publicKeyIndex == -1) {
        std::cerr << "STM32 header v2.2 requires a public key index (-x)" << std::endl;
        return -1;
    }
    if (publicKeyIndex < 0 || publicKeyIndex >= static_cast<int>(PUBLIC_KEY_COUNT)) {
        std::cerr << "STM32 header v2.2 public key index must be between 0 and 7" << std::endl;
        return -1;
    }
    EVP_PKEY* rawKey = nullptr;
    if (openSslKeys->loadKey(keyDesc, passphrase, &rawKey) != 0) {
        std::cerr << "Failed to load key: " << keyDesc << std::endl;
        return -1;
    }
    EvpPkeyPtr key(rawKey);

    STM32HeaderV2_2 header = unpackHeader(image);

    std::memset(header.base_header.reserved, 0, sizeof(header.base_header.reserved));
    std::memset(header.base_header.padding, 0, sizeof(header.base_header.padding));

    std::vector<unsigned char> pubkey = openSslKeys->getRawPubkey(key.get());
    if (pubkey.empty()) {
        return -1;
    }
    logger->printHex("Public Key", pubkey);

    int algo = openSslKeys->getKeyAlgorithm(key.get());
    if (algo < 0) {
        return -1;
    }

    if (prepareAuthenticationExtension(header) != 0) {
        return -1;
    }
    const auto& auth = *header.authentication_extension;
    if (pubkey.size() != sizeof(auth.ecdsa_public_key)
        || std::memcmp(pubkey.data(), auth.ecdsa_public_key, pubkey.size()) != 0
        || static_cast<uint32_t>(algo) != auth.ecdsa_algorithm) {
        std::cerr << "Signing key (-k) does not match public key " << publicKeyIndex
                  << " of the key table (-K/-x)" << std::endl;
        return -1;
    }
    uint32_t payloadLength = header.base_header.length;
    if (alignPayload(image, HEADER_SIZE, payloadLength) != 0) {
        return -1;
    }
    header.base_header.length = payloadLength;
    repackHeader(image, header);

    size_t hashEnd = HEADER_SIZE + header.base_header.length;
    std::vector<unsigned char> bufferToHash = getSignedData(image, hashEnd);

    EvpMdCtxPtr mdCtx(EVP_MD_CTX_new());
    std::vector<unsigned char> der;
    size_t derLen = 0;
    if (!mdCtx
        || EVP_DigestSignInit(mdCtx.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1
        || EVP_DigestSign(mdCtx.get(),
                          nullptr,
                          &derLen,
                          bufferToHash.data(),
                          bufferToHash.size())
               != 1) {
        std::cerr << "Failed to initialize signing" << std::endl;
        return -1;
    }
    der.resize(derLen);
    if (EVP_DigestSign(mdCtx.get(),
                       der.data(),
                       &derLen,
                       bufferToHash.data(),
                       bufferToHash.size())
        != 1) {
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

    std::vector<unsigned char> signature(sizeof(header.base_header.signature));
    constexpr int half = static_cast<int>(sizeof(header.base_header.signature) / 2);
    if (BN_bn2binpad(r, signature.data(), half) != half
        || BN_bn2binpad(s, signature.data() + half, half) != half) {
        std::cerr << "Failed to convert BIGNUM to binary" << std::endl;
        return -1;
    }
    if (logger->isVerbose()) {
        logger->printHex("ECC key(r)",
                         std::vector<unsigned char>(signature.begin(), signature.begin() + half));
        logger->printHex("ECC key(s)",
                         std::vector<unsigned char>(signature.begin() + half, signature.end()));
    }
    logger->printHex("Signature", signature);

    std::memcpy(image.data() + offsetof(STM32BaseHeaderV2_2, signature),
                signature.data(),
                signature.size());

    return verify(image);
}

int STM32ImageFormatV2_2::prepareAuthenticationExtension(STM32HeaderV2_2& header) {
    STM32AuthenticationExtensionV2_2 authenticationExtension{};

    const unsigned char extensionType[4] = {'S', 'T', 0x00, 0x02};
    std::memcpy(&authenticationExtension.extension_type,
                extensionType,
                sizeof(extensionType));
    authenticationExtension.extension_length =
        static_cast<uint32_t>(sizeof(authenticationExtension));
    authenticationExtension.public_key_index = static_cast<uint32_t>(publicKeyIndex);
    authenticationExtension.public_key_count = static_cast<uint32_t>(PUBLIC_KEY_COUNT);

    for (size_t index = 0; index < PUBLIC_KEY_COUNT; ++index) {
        EVP_PKEY* rawKey = nullptr;
        if (openSslKeys->loadPublicKey(publicKeyDescriptors[index], &rawKey) != 0) {
            std::cerr << "Failed to load public key: " << publicKeyDescriptors[index]
                      << std::endl;
            return -1;
        }
        EvpPkeyPtr key(rawKey);

        const std::vector<unsigned char> publicKey = openSslKeys->getRawPubkey(key.get());
        if (publicKey.size() != sizeof(authenticationExtension.ecdsa_public_key)) {
            std::cerr << "Invalid public key size: " << publicKeyDescriptors[index]
                      << std::endl;
            return -1;
        }

        const int keyAlgorithm = openSslKeys->getKeyAlgorithm(key.get());
        if (keyAlgorithm < 0) {
            return -1;
        }
        const uint32_t algorithm = static_cast<uint32_t>(keyAlgorithm);

        if (!OpenSslKeys::computePublicKeyHash(publicKey.data(), publicKey.size(), algorithm,
                                             authenticationExtension.public_key_hashes[index])) {
            std::cerr << "Failed to hash public key: " << publicKeyDescriptors[index]
                      << std::endl;
            return -1;
        }

        if (index == static_cast<size_t>(publicKeyIndex)) {
            authenticationExtension.ecdsa_algorithm = algorithm;
            std::memcpy(authenticationExtension.ecdsa_public_key,
                        publicKey.data(),
                        publicKey.size());
        }
    }

    if (OpenSslKeys::validatePublicKeyHashes(
            reinterpret_cast<const unsigned char*>(authenticationExtension.public_key_hashes),
            PUBLIC_KEY_COUNT) != 0) {
        return -1;
    }

    header.authentication_extension = authenticationExtension;
    header.base_header.option_flags |= 1U;
    return 0;
}
