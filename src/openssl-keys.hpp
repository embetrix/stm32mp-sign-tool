// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Key material: loading a private key from a PEM file or a PKCS#11 URI, and
// deriving public key data from it.

#include "openssl-ptr.hpp"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <openssl/provider.h>
#include <openssl/ui.h>

class Logger;

class OpenSslKeys {
public:
    void setPkcs11Module(const std::string& modulePath);

    int getEcPubkey(const unsigned char* pubkey, size_t pubkeyLen, uint32_t algo, EVP_PKEY** pkey);
    std::vector<unsigned char> getRawPubkey(EVP_PKEY* key);
    int getKeyAlgorithm(EVP_PKEY* key);
    int loadKey(const std::string& keyDesc, const std::optional<std::string>& passphrase, EVP_PKEY** pkey);
    int hashPubkey(const std::string& keyDesc, const std::optional<std::string>& passphrase, const std::string& outputFile, const Logger& logger);

private:
    struct OssProviderDeleter {
        void operator()(OSSL_PROVIDER* ptr) const { OSSL_PROVIDER_unload(ptr); }
    };

    using OssProviderPtr = std::unique_ptr<OSSL_PROVIDER, OssProviderDeleter>;

    std::string pkcs11Module;
    OssProviderPtr pkcs11Provider;
    OssProviderPtr defaultProvider;

    static int uiReadString(UI* ui, UI_STRING* uis);
};
