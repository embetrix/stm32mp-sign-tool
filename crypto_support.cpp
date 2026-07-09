// SPDX-License-Identifier: GPL-3.0-or-later

#include "crypto_support.hpp"

#include "openssl_raii.hpp"

#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <openssl/core_names.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/sha.h>
#include <openssl/store.h>
#include <openssl/ui.h>

namespace {

bool verbose = false;
const char* pkcs11_module = nullptr;
OssProviderPtr pkcs11_provider;
OssProviderPtr default_provider;

// UI_METHOD reader callback used to feed the PKCS#11 PIN (or PEM passphrase)
// stored as user data to OSSL_STORE without prompting interactively.
int ui_read_string(UI* ui, UI_STRING* uis) {
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

} // namespace

void set_verbose(bool enabled) {
    verbose = enabled;
}

bool is_verbose_enabled() {
    return verbose;
}

void set_pkcs11_module(const char* module_path) {
    pkcs11_module = module_path;
}

void cleanup_crypto_providers() {
    if (pkcs11_provider) {
        pkcs11_provider.reset();
    }
    if (default_provider) {
        default_provider.reset();
    }
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

int get_ec_pubkey(const unsigned char* pubkey, size_t pubkey_len, uint32_t algo, EVP_PKEY** pkey) {
    *pkey = nullptr;
    if (!pubkey) {
        std::cerr << "Public key is empty" << std::endl;
        return -1;
    }
    if (pubkey_len != 64) {
        std::cerr << "Invalid public key length" << std::endl;
        return -1;
    }
    const char* group_name;
    if (algo == 1) {
        group_name = SN_X9_62_prime256v1;
    } else if (algo == 2) {
        group_name = SN_brainpoolP256t1;
    } else {
        std::cerr << "Unsupported ECDSA algorithm" << std::endl;
        return -1;
    }

    // Build the uncompressed EC point: 0x04 || X || Y
    std::vector<unsigned char> point(1 + pubkey_len);
    point[0] = 0x04;
    std::memcpy(point.data() + 1, pubkey, pubkey_len);

    OssParamBldPtr bld(OSSL_PARAM_BLD_new());
    if (!bld) {
        std::cerr << "Failed to create OSSL_PARAM_BLD" << std::endl;
        return -1;
    }
    if (!OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME,
                                         group_name, 0) ||
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
    EVP_PKEY* raw_pkey = nullptr;
    int ret = -1;
    if (ctx &&
        EVP_PKEY_fromdata_init(ctx.get()) > 0 &&
        EVP_PKEY_fromdata(ctx.get(), &raw_pkey, EVP_PKEY_PUBLIC_KEY, params.get()) > 0) {
        *pkey = raw_pkey;
        ret = 0;
    } else {
        std::cerr << "Failed to create EVP_PKEY from public key" << std::endl;
        EvpPkeyPtr failed_pkey(raw_pkey);
    }
    return ret;
}

std::vector<unsigned char> get_raw_pubkey(EVP_PKEY* key) {
    if (!key) {
        std::cerr << "Invalid EVP_PKEY" << std::endl;
        return {};
    }
    // Export the public key params. Unlike the per-parameter getters,
    // EVP_PKEY_todata works uniformly across the default provider (file
    // keys) and the PKCS#11 provider, which only implements key export.
    OSSL_PARAM* raw_params = nullptr;
    if (EVP_PKEY_todata(key, EVP_PKEY_PUBLIC_KEY, &raw_params) != 1 || !raw_params) {
        std::cerr << "Failed to export public key from EVP_PKEY" << std::endl;
        return {};
    }
    OssParamPtr params(raw_params);

    std::vector<unsigned char> pubkey;
    const OSSL_PARAM* pub = OSSL_PARAM_locate_const(params.get(), OSSL_PKEY_PARAM_PUB_KEY);
    if (pub && pub->data_size == 65) {
        // Uncompressed EC point: 0x04 || X || Y
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

int get_key_algorithm(EVP_PKEY* key) {
    if (!key) {
        std::cerr << "Invalid EVP_PKEY" << std::endl;
        return -1;
    }
    char group_name[64];
    size_t len = 0;
    if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME,
                                       group_name, sizeof(group_name), &len) != 1) {
        std::cerr << "Failed to get EC group name" << std::endl;
        return -1;
    }
    if (std::strcmp(group_name, SN_X9_62_prime256v1) == 0) {
        return 1;
    }
    else if (std::strcmp(group_name, SN_brainpoolP256t1) == 0) {
        return 2;
    }
    std::cerr << "Unsupported ECDSA curve: " << group_name << std::endl;
    return -1;
}

int load_key(const char* key_desc, const char* passphrase, EVP_PKEY** pkey) {
    *pkey = nullptr;
    if (!key_desc || std::strlen(key_desc) == 0) {
        std::cerr << "Invalid arguments" << std::endl;
        return -1;
    }

    if (std::strncmp(key_desc, "pkcs11:", 7) == 0) {
        // Load key using the PKCS#11 provider via OSSL_STORE.

        // Allow overriding the PKCS#11 module through the provider's
        // environment variable before the provider is loaded.
        if (pkcs11_module) {
            setenv("PKCS11_PROVIDER_MODULE", pkcs11_module, 1);
        }

        // The default provider is required alongside pkcs11 (e.g. for hashing).
        if (!default_provider) {
            default_provider.reset(OSSL_PROVIDER_load(nullptr, "default"));
        }
        if (!pkcs11_provider) {
            pkcs11_provider.reset(OSSL_PROVIDER_load(nullptr, "pkcs11"));
        }
        if (!pkcs11_provider) {
            std::cerr << "Failed to load PKCS#11 provider" << std::endl;
            return -1;
        }

        UiMethodPtr ui_method;
        if (passphrase) {
            ui_method.reset(UI_create_method("stm32mp-sign-tool pin reader"));
            if (!ui_method || UI_method_set_reader(ui_method.get(), ui_read_string) != 0) {
                std::cerr << "Failed to set up PIN reader" << std::endl;
                return -1;
            }
        }

        OssStoreCtxPtr store(OSSL_STORE_open(key_desc, ui_method.get(),
                                             const_cast<char*>(passphrase),
                                             nullptr, nullptr));
        if (!store) {
            std::cerr << "Failed to open PKCS#11 store: " << key_desc << std::endl;
            return -1;
        }

        // Look for the private key in the store.
        EvpPkeyPtr loaded_pkey;
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
                loaded_pkey.reset(OSSL_STORE_INFO_get1_PKEY(info.get()));
                break;
            }
        }

        if (!loaded_pkey) {
            std::cerr << "Failed to load private key from PKCS#11: " << key_desc << std::endl;
            return -1;
        }
        *pkey = loaded_pkey.release();
    }
    else {
        // Load key from file
        FilePtr key_fp(fopen(key_desc, "r"));
        if (!key_fp) {
            std::cerr << "Failed to open key file" << std::endl;
            return -1;
        }

        EvpPkeyPtr loaded_pkey(PEM_read_PrivateKey(key_fp.get(), nullptr, nullptr,
                                                   static_cast<void*>(const_cast<char*>(passphrase))));
        if (!loaded_pkey) {
            std::cerr << "Failed to read key from file" << std::endl;
            return -1;
        }
        *pkey = loaded_pkey.release();
    }

    return 0;
}

int hash_pubkey(const char* key_desc, const char* passphrase, const std::string& output_file) {
    if (!key_desc || output_file.empty()) {
        std::cerr << "Invalid arguments" << std::endl;
        return -1;
    }
    EVP_PKEY* raw_key = nullptr;
    if (load_key(key_desc, passphrase, &raw_key) != 0) {
        std::cerr << "Failed to load key: " << key_desc << std::endl;
        return -1;
    }
    if (!raw_key) {
        std::cerr << "Invalid key" << std::endl;
        return -1;
    }
    EvpPkeyPtr key(raw_key);
    std::vector<unsigned char> pubkey = get_raw_pubkey(key.get());
    if (pubkey.empty()) {
        std::cerr << "Failed to get raw public key" << std::endl;
        return -1;
    }

    std::vector<unsigned char> phash(SHA256_DIGEST_LENGTH);
    SHA256(pubkey.data(), pubkey.size(), phash.data());
    print_hex("Pubkey(sha256)", phash);

    std::ofstream output(output_file, std::ios::binary);
    if (!output) {
        std::cerr << "Failed to open output file: " << output_file << std::endl;
        return -1;
    }
    output.write(reinterpret_cast<const char*>(phash.data()), static_cast<std::streamsize>(phash.size()));
    output.close();

    return 0;
}
