// SPDX-License-Identifier: GPL-3.0-or-later

#include "openssl-support.hpp"

#include "utils.hpp"

#include <cstring>
#include <fstream>
#include <iostream>

#include <openssl/core_names.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/store.h>

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* ptr) const { EVP_PKEY_CTX_free(ptr); }
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

struct UiMethodDeleter {
    void operator()(UI_METHOD* ptr) const { UI_destroy_method(ptr); }
};

struct FileDeleter {
    void operator()(FILE* ptr) const { fclose(ptr); }
};

using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using OssParamBldPtr = std::unique_ptr<OSSL_PARAM_BLD, OssParamBldDeleter>;
using OssParamPtr = std::unique_ptr<OSSL_PARAM, OssParamDeleter>;
using OssStoreCtxPtr = std::unique_ptr<OSSL_STORE_CTX, OssStoreCtxDeleter>;
using OssStoreInfoPtr = std::unique_ptr<OSSL_STORE_INFO, OssStoreInfoDeleter>;
using UiMethodPtr = std::unique_ptr<UI_METHOD, UiMethodDeleter>;
using FilePtr = std::unique_ptr<FILE, FileDeleter>;

int OpenSSLSupport::uiReadString(UI* ui, UI_STRING* uis) {
    switch (UI_get_string_type(uis)) {
        case UIT_PROMPT:
        case UIT_VERIFY: {
            const char* secret = static_cast<const char*>(UI_get0_user_data(ui));
            if (secret) {
                return UI_set_result(ui, uis, secret) >= 0 ? 1 : 0;
            }
            return 1;
        }
        default:
            return 1;
    }
}

void OpenSSLSupport::setPkcs11Module(const std::string& modulePath) {
    pkcs11Module = modulePath;
}

int OpenSSLSupport::getEcPubkey(const unsigned char* pubkey, size_t pubkeyLen, uint32_t algo, EVP_PKEY** pkey) {
    *pkey = nullptr;
    if (!pubkey) {
        std::cerr << "Public key is empty" << std::endl;
        return -1;
    }
    if (pubkeyLen != 64) {
        std::cerr << "Invalid public key length" << std::endl;
        return -1;
    }
    std::string groupName;
    if (algo == 1) {
        groupName = SN_X9_62_prime256v1;
    } else if (algo == 2) {
        groupName = SN_brainpoolP256t1;
    } else {
        std::cerr << "Unsupported ECDSA algorithm" << std::endl;
        return -1;
    }

    std::vector<unsigned char> point(1 + pubkeyLen);
    point[0] = 0x04;
    std::memcpy(point.data() + 1, pubkey, pubkeyLen);

    OssParamBldPtr bld(OSSL_PARAM_BLD_new());
    if (!bld) {
        std::cerr << "Failed to create OSSL_PARAM_BLD" << std::endl;
        return -1;
    }
    if (!OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME,
                                         groupName.c_str(), 0) ||
        !OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                          point.data(), point.size())) {
        std::cerr << "Failed to set public key parameters" << std::endl;
        return -1;
    }
    OssParamPtr params(OSSL_PARAM_BLD_to_param(bld.get()));
    if (!params) {
        std::cerr << "Failed to build public key parameters" << std::endl;
        return -1;
    }

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    EVP_PKEY* rawPkey = nullptr;
    int ret = -1;
    if (ctx &&
        EVP_PKEY_fromdata_init(ctx.get()) > 0 &&
        EVP_PKEY_fromdata(ctx.get(), &rawPkey, EVP_PKEY_PUBLIC_KEY, params.get()) > 0) {
        *pkey = rawPkey;
        ret = 0;
    } else {
        std::cerr << "Failed to create EVP_PKEY from public key" << std::endl;
        EvpPkeyPtr failedPkey(rawPkey);
    }
    return ret;
}

std::vector<unsigned char> OpenSSLSupport::getRawPubkey(EVP_PKEY* key) {
    if (!key) {
        std::cerr << "Invalid EVP_PKEY" << std::endl;
        return {};
    }
    OSSL_PARAM* rawParams = nullptr;
    if (EVP_PKEY_todata(key, EVP_PKEY_PUBLIC_KEY, &rawParams) != 1 || !rawParams) {
        std::cerr << "Failed to export public key from EVP_PKEY" << std::endl;
        return {};
    }
    OssParamPtr params(rawParams);

    std::vector<unsigned char> pubkey;
    const OSSL_PARAM* pub = OSSL_PARAM_locate_const(params.get(), OSSL_PKEY_PARAM_PUB_KEY);
    if (pub && pub->data_size == 65) {
        const unsigned char* point = static_cast<const unsigned char*>(pub->data);
        if (point[0] == 0x04) {
            pubkey.assign(point + 1, point + pub->data_size);
        }
    }

    if (pubkey.empty()) {
        std::cerr << "Unexpected public key encoding" << std::endl;
    }
    return pubkey;
}

int OpenSSLSupport::getKeyAlgorithm(EVP_PKEY* key) {
    if (!key) {
        std::cerr << "Invalid EVP_PKEY" << std::endl;
        return -1;
    }
    char groupName[64];
    size_t len = 0;
    if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME,
                                       groupName, sizeof(groupName), &len) != 1) {
        std::cerr << "Failed to get EC group name" << std::endl;
        return -1;
    }
    if (std::strcmp(groupName, SN_X9_62_prime256v1) == 0) {
        return 1;
    }
    else if (std::strcmp(groupName, SN_brainpoolP256t1) == 0) {
        return 2;
    }
    std::cerr << "Unsupported ECDSA curve: " << groupName << std::endl;
    return -1;
}

int OpenSSLSupport::loadKey(const std::string& keyDesc, const std::string& passphrase, EVP_PKEY** pkey) {
    *pkey = nullptr;
    if (keyDesc.empty()) {
        std::cerr << "Invalid arguments" << std::endl;
        return -1;
    }

    if (keyDesc.rfind("pkcs11:", 0) == 0) {
        if (!pkcs11Module.empty()) {
            setenv("PKCS11_PROVIDER_MODULE", pkcs11Module.c_str(), 1);
        }

        if (!defaultProvider) {
            defaultProvider.reset(OSSL_PROVIDER_load(nullptr, "default"));
        }
        if (!pkcs11Provider) {
            pkcs11Provider.reset(OSSL_PROVIDER_load(nullptr, "pkcs11"));
        }
        if (!pkcs11Provider) {
            std::cerr << "Failed to load PKCS#11 provider" << std::endl;
            return -1;
        }

        UiMethodPtr uiMethod;
        if (!passphrase.empty()) {
            uiMethod.reset(UI_create_method("stm32mp-sign-tool pin reader"));
            if (!uiMethod || UI_method_set_reader(uiMethod.get(), uiReadString) != 0) {
                std::cerr << "Failed to set up PIN reader" << std::endl;
                return -1;
            }
        }

        OssStoreCtxPtr store(OSSL_STORE_open(keyDesc.c_str(), uiMethod.get(),
                                             passphrase.empty() ? nullptr : const_cast<char*>(passphrase.c_str()),
                                             nullptr, nullptr));
        if (!store) {
            std::cerr << "Failed to open PKCS#11 store: " << keyDesc << std::endl;
            return -1;
        }

        EvpPkeyPtr loadedPkey;
        OSSL_STORE_expect(store.get(), OSSL_STORE_INFO_PKEY);
        while (!OSSL_STORE_eof(store.get())) {
            OssStoreInfoPtr info(OSSL_STORE_load(store.get()));
            if (!info) {
                if (OSSL_STORE_error(store.get())) {
                    continue;
                }
                break;
            }
            if (OSSL_STORE_INFO_get_type(info.get()) == OSSL_STORE_INFO_PKEY) {
                loadedPkey.reset(OSSL_STORE_INFO_get1_PKEY(info.get()));
                break;
            }
        }

        if (!loadedPkey) {
            std::cerr << "Failed to load private key from PKCS#11: " << keyDesc << std::endl;
            return -1;
        }
        *pkey = loadedPkey.release();
    }
    else {
        FilePtr keyFp(fopen(keyDesc.c_str(), "r"));
        if (!keyFp) {
            std::cerr << "Failed to open key file" << std::endl;
            return -1;
        }

        EvpPkeyPtr loadedPkey(PEM_read_PrivateKey(keyFp.get(), nullptr, nullptr,
                                                   passphrase.empty() ? nullptr : static_cast<void*>(const_cast<char*>(passphrase.c_str()))));
        if (!loadedPkey) {
            std::cerr << "Failed to read key from file" << std::endl;
            return -1;
        }
        *pkey = loadedPkey.release();
    }

    return 0;
}

int OpenSSLSupport::hashPubkey(const std::string& keyDesc, const std::string& passphrase, const std::string& outputFile, const Utils& utils) {
    if (keyDesc.empty() || outputFile.empty()) {
        std::cerr << "Invalid arguments" << std::endl;
        return -1;
    }
    EVP_PKEY* rawKey = nullptr;
    if (loadKey(keyDesc, passphrase, &rawKey) != 0) {
        std::cerr << "Failed to load key: " << keyDesc << std::endl;
        return -1;
    }
    if (!rawKey) {
        std::cerr << "Invalid key" << std::endl;
        return -1;
    }
    EvpPkeyPtr key(rawKey);
    std::vector<unsigned char> pubkey = getRawPubkey(key.get());
    if (pubkey.empty()) {
        std::cerr << "Failed to get raw public key" << std::endl;
        return -1;
    }

    std::vector<unsigned char> phash(SHA256_DIGEST_LENGTH);
    SHA256(pubkey.data(), pubkey.size(), phash.data());
    utils.printHex("Pubkey(sha256)", phash);

    std::ofstream output(outputFile, std::ios::binary);
    if (!output) {
        std::cerr << "Failed to open output file: " << outputFile << std::endl;
        return -1;
    }
    output.write((const char*)phash.data(), static_cast<std::streamsize>(phash.size()));
    output.close();

    return 0;
}
