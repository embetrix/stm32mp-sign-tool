// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <openssl/evp.h>

void set_verbose(bool enabled);
bool is_verbose_enabled();
void set_pkcs11_module(const char* module_path);
void cleanup_crypto_providers();

void print_hex(const std::string& label, const std::vector<unsigned char>& data);
int get_ec_pubkey(const unsigned char* pubkey, size_t pubkey_len, uint32_t algo, EVP_PKEY** pkey);
std::vector<unsigned char> get_raw_pubkey(EVP_PKEY* key);
int get_key_algorithm(EVP_PKEY* key);
int load_key(const char* key_desc, const char* passphrase, EVP_PKEY** pkey);
int hash_pubkey(const char* key_desc, const char* passphrase, const std::string& output_file);
