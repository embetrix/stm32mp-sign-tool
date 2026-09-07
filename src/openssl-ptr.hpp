// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// RAII wrappers for the OpenSSL C types used across the tool. Kept apart from
// openssl-keys.hpp so code that only juggles OpenSSL objects does not have to
// pull in the key-loading class.

#include <memory>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

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
