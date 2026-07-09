// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdio>
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/ui.h>

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* ptr) const { EVP_PKEY_free(ptr); }
};

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* ptr) const { EVP_PKEY_CTX_free(ptr); }
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

struct OssParamBldDeleter {
    void operator()(OSSL_PARAM_BLD* ptr) const { OSSL_PARAM_BLD_free(ptr); }
};

struct OssParamDeleter {
    void operator()(OSSL_PARAM* ptr) const { OSSL_PARAM_free(ptr); }
};

struct OssStoreCtxDeleter {
    void operator()(OSSL_STORE_CTX* ptr) const { OSSL_STORE_close(ptr); }
};

struct OssStoreInfoDeleter {
    void operator()(OSSL_STORE_INFO* ptr) const { OSSL_STORE_INFO_free(ptr); }
};

struct OssProviderDeleter {
    void operator()(OSSL_PROVIDER* ptr) const { OSSL_PROVIDER_unload(ptr); }
};

struct UiMethodDeleter {
    void operator()(UI_METHOD* ptr) const { UI_destroy_method(ptr); }
};

struct OpenSslBufferDeleter {
    void operator()(unsigned char* ptr) const { OPENSSL_free(ptr); }
};

struct FileDeleter {
    void operator()(FILE* ptr) const { fclose(ptr); }
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
using EcdsaSigPtr = std::unique_ptr<ECDSA_SIG, EcdsaSigDeleter>;
using BignumPtr = std::unique_ptr<BIGNUM, BignumDeleter>;
using OssParamBldPtr = std::unique_ptr<OSSL_PARAM_BLD, OssParamBldDeleter>;
using OssParamPtr = std::unique_ptr<OSSL_PARAM, OssParamDeleter>;
using OssStoreCtxPtr = std::unique_ptr<OSSL_STORE_CTX, OssStoreCtxDeleter>;
using OssStoreInfoPtr = std::unique_ptr<OSSL_STORE_INFO, OssStoreInfoDeleter>;
using OssProviderPtr = std::unique_ptr<OSSL_PROVIDER, OssProviderDeleter>;
using UiMethodPtr = std::unique_ptr<UI_METHOD, UiMethodDeleter>;
using OpenSslBufferPtr = std::unique_ptr<unsigned char, OpenSslBufferDeleter>;
using FilePtr = std::unique_ptr<FILE, FileDeleter>;
