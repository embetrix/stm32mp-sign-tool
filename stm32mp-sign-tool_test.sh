#!/bin/sh -ex
#
# Copyright (c) 2024
# Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
#

dd if=/dev/urandom of=image.bin bs=1M count=1 > /dev/null 2>&1

python3 stm32mp-gen-image.py image.stm32 image.bin

# test plain key file
openssl ecparam -name prime256v1 -genkey -out private_key.pem
./stm32mp-sign-tool -v -k private_key.pem -i image.stm32 -o image.stm32.signed

# test plain key file with password
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -aes-256-cbc -out private_key.pem -pass pass:pa33w0rd
./stm32mp-sign-tool -v -k private_key.pem -p "pa33w0rd" -i image.stm32 -o image.stm32.signed

# test plain key file (brainpool)
openssl ecparam -name brainpoolP256t1 -genkey -out brainpool_private_key.pem
./stm32mp-sign-tool -v -k brainpool_private_key.pem -i image.stm32 -o image.stm32.signed

# test plain key file with password (brainpool)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP256t1 -aes-256-cbc -out brainpool_private_key.pem -pass pass:pa33w0rd
./stm32mp-sign-tool -v -k brainpool_private_key.pem -p "pa33w0rd" -i image.stm32 -o image.stm32.signed

# test pkcs11 key
export PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so
export PIN="12345"
export SO_PIN="1234"
export SOFTHSM2_CONF=$PWD/.softhsm/softhsm2.conf
export TOKEN_NAME="token0"

mkdir -p .softhsm/tokens
echo "directories.tokendir = $PWD/.softhsm/tokens" > .softhsm/softhsm2.conf
pkcs11-tool --pin $PIN --module $PKCS11_MODULE_PATH --slot-index=0 --init-token --label=$TOKEN_NAME --so-pin $SO_PIN --init-pin
pkcs11-tool --pin $PIN --module $PKCS11_MODULE_PATH --keypairgen --key-type EC:prime256v1 --id 1 --label "testkeyECp256"
./stm32mp-sign-tool -v -k "pkcs11:object=testkeyECp256" -p 12345 -i image.stm32 -o image.stm32.signed -h hash_pkcs11_p256.bin
./stm32mp-sign-tool -v -k "pkcs11:object=testkeyECp256?pin-value=12345"  -i image.stm32 -o image.stm32.signed

# Skip for the moment test pkcs11 sign with (brainpoolP256t1)
# will be fixed in later releases: https://github.com/OpenSC/OpenSC/pull/3601
# pkcs11-tool --pin $PIN --module $PKCS11_MODULE_PATH --keypairgen --key-type EC:brainpoolP256t1 --id 2 --label "testkeyECbrainpoolP256t1"
# ./stm32mp-sign-tool -v -k "pkcs11:object=testkeyECbrainpoolP256t1" -p 12345 -i image.stm32 -o image.stm32.signed -h hash_pkcs11_brainpool.bin
# ./stm32mp-sign-tool -v -k "pkcs11:object=testkeyECbrainpoolP256t1?pin-value=12345"  -i image.stm32 -o image.stm32.signed

# test public key hash generation from pkcs11 public key (prime256v1)
./stm32mp-sign-tool -v -u "pkcs11:object=testkeyECp256" -p 12345 -h hash_from_pkcs11_public.bin
cmp hash_pkcs11_p256.bin hash_from_pkcs11_public.bin

# test public key hash generation from pkcs11 public key with pin in URI (prime256v1)
./stm32mp-sign-tool -v -u "pkcs11:object=testkeyECp256?pin-value=12345" -h hash_from_pkcs11_public_uri.bin
cmp hash_pkcs11_p256.bin hash_from_pkcs11_public_uri.bin

# test public key hash generation from pkcs11 public key (brainpoolP256t1)
# skipped because softhsm2/OpenSC do not support creating this key in this test setup
# ./stm32mp-sign-tool -v -u "pkcs11:object=testkeyECbrainpoolP256t1" -p 12345 -h hash_from_pkcs11_brainpool_public.bin
# cmp hash_pkcs11_brainpool.bin hash_from_pkcs11_brainpool_public.bin

# test sign process with external signing using pkcs11 public key
./stm32mp-sign-tool -v -u "pkcs11:object=testkeyECp256" -p 12345 -i image.stm32 -s image-sha256-pkcs11.bin
# sign with private key from pkcs11
pkcs11-tool --pin $PIN --module $PKCS11_MODULE_PATH --sign --mechanism ECDSA --id 1 --input-file image-sha256-pkcs11.bin --output-file signature-pkcs11.der
# apply the signature to create the signed image using pkcs11 public key
./stm32mp-sign-tool -v -u "pkcs11:object=testkeyECp256" -p 12345 -i image.stm32 -d signature-pkcs11.der -o image.stm32.signed.pkcs11

# test public key hash generation from private and public key
openssl ecparam -name prime256v1 -genkey -out private_key.pem
openssl ec -in private_key.pem -pubout -out public_key.pem
./stm32mp-sign-tool -v -k private_key.pem -p "pa33w0rd" -h hash_from_private.bin
./stm32mp-sign-tool -v -u public_key.pem -h hash_from_public.bin
cmp hash_from_private.bin hash_from_public.bin

# Test sign process with external signing
# generate hash to sign from image
./stm32mp-sign-tool -u public_key.pem -i image.stm32 -s image-sha256.bin
# sign image sha256 eg. with openssl
openssl pkeyutl -sign -inkey private_key.pem -in image-sha256.bin -out signature.der
# apply the signature to create the signed image
./stm32mp-sign-tool -u public_key.pem -i image.stm32 -d signature.der -o image.stm32.signed

