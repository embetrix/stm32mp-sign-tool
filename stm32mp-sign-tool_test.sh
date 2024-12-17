#!/bin/sh -ex
#
# Copyright (c) 2024
# Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
# 


dd if=/dev/urandom of=image.bin bs=1M count=1 > /dev/null 2>&1

python3 stm32mp-gen-image.py image.stm32 image.bin


# test plain key file
openssl ecparam -name prime256v1 -genkey -out private_key.pem
./stm32mp-sign-tool -v -k  private_key.pem -i image.stm32 -o image.stm32.signed

# test plain key file with password
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -aes-256-cbc -out private_key.pem -pass pass:pa33w0rd
./stm32mp-sign-tool -v -k  private_key.pem -p "pa33w0rd" -i image.stm32 -o image.stm32.signed

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
./stm32mp-sign-tool -v -k  "pkcs11:object=testkeyECp256" -p 12345 -i image.stm32  -o image.stm32.signed -h hash.bin
