// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <memory>
#include <string>
#include <vector>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/ui.h>

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* ptr) const { EVP_PKEY_free(ptr); }
};

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX* ptr) const { EVP_MD_CTX_free(ptr); }
};

struct EcdsaSigDeleter {
    void operator()(ECDSA_SIG* ptr) const { ECDSA_SIG_free(ptr); }
};

struct BignumDeleter {
    void operator()(BIGNUM* ptr) const { BN_free(ptr); }
};

struct OpenSslBufferDeleter {
    void operator()(unsigned char* ptr) const { OPENSSL_free(ptr); }
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
using EcdsaSigPtr = std::unique_ptr<ECDSA_SIG, EcdsaSigDeleter>;
using BignumPtr = std::unique_ptr<BIGNUM, BignumDeleter>;
using OpenSslBufferPtr = std::unique_ptr<unsigned char, OpenSslBufferDeleter>;

class Utils;

class OpenSSLSupport {
public:
    void setPkcs11Module(const std::string& modulePath);

    int getEcPubkey(const unsigned char* pubkey, size_t pubkeyLen, uint32_t algo, EVP_PKEY** pkey);
    std::vector<unsigned char> getRawPubkey(EVP_PKEY* key);
    int getKeyAlgorithm(EVP_PKEY* key);
    int loadKey(const std::string& keyDesc, const std::string& passphrase, EVP_PKEY** pkey);
    int hashPubkey(const std::string& keyDesc, const std::string& passphrase, const std::string& outputFile, const Utils& utils);

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
