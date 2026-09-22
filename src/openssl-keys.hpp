// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Key material: loading private and public keys from PEM files or PKCS#11
// URIs, and deriving raw public key data from them.

#include "openssl-ptr.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <openssl/provider.h>
#include <openssl/sha.h>
#include <openssl/ui.h>

class Logger;

class OpenSslKeys {
public:
    static constexpr std::size_t PUBLIC_KEY_COUNT = 8;
    static constexpr std::size_t PUBLIC_KEY_SIZE = 64;

    static bool computePublicKeyHash(const unsigned char* publicKey,
                                     std::size_t publicKeySize,
                                     uint32_t algorithm,
                                     unsigned char* hash);
    static int validatePublicKeyHashes(const unsigned char* hashes, std::size_t count);

    void setPkcs11Module(const std::string& modulePath);

    int getEcPubkey(const unsigned char* pubkey, size_t pubkeyLen, uint32_t algo, EVP_PKEY** pkey);
    std::vector<unsigned char> getRawPubkey(EVP_PKEY* key);
    int getKeyAlgorithm(EVP_PKEY* key);
    int loadKey(const std::string& keyDesc, const std::optional<std::string>& passphrase, EVP_PKEY** pkey);
    int loadPublicKey(const std::string& keyDesc, EVP_PKEY** pkey);
    int hashPubkey(const std::string& keyDesc, const std::optional<std::string>& passphrase, const std::string& outputFile, const Logger& logger);

private:
    struct OssProviderDeleter {
        void operator()(OSSL_PROVIDER* ptr) const { OSSL_PROVIDER_unload(ptr); }
    };

    using OssProviderPtr = std::unique_ptr<OSSL_PROVIDER, OssProviderDeleter>;

    std::string pkcs11Module;
    OssProviderPtr pkcs11Provider;
    OssProviderPtr defaultProvider;

    int loadKeyFromPkcs11(const std::string& keyDesc, const std::optional<std::string>& passphrase, EVP_PKEY** pkey);
    int loadKeyFromPem(const std::string& keyDesc, const std::optional<std::string>& passphrase, EVP_PKEY** pkey);
    int loadPublicKeyFromPkcs11(const std::string& keyDesc, EVP_PKEY** pkey);
    int loadPublicKeyFromPem(const std::string& keyDesc, EVP_PKEY** pkey);

    int initializePkcs11Provider();

    static int uiReadString(UI* ui, UI_STRING* uis);
};
