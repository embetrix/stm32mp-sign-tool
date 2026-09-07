#!/bin/sh -ex
#
# Copyright (c) 2024
# Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
# 

# The generator scripts live next to this script; the signing tool is picked up
# from the build directory (the working directory used by ctest).
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SIGN_TOOL=${SIGN_TOOL:-$PWD/stm32mp-sign-tool}

dd if=/dev/urandom of=image.bin bs=1M count=1 > /dev/null 2>&1

python3 "$SCRIPT_DIR/stm32mp-gen-image.py" image.stm32 image.bin

# test plain key file
openssl ecparam -name prime256v1 -genkey -out private_key.pem
"$SIGN_TOOL" -v -k private_key.pem -i image.stm32 -o image.stm32.signed

# images with an unsupported header version (v2, STM32MP13x/STM32MP2 series) must be rejected
python3 -c "
data = bytearray(open('image.stm32', 'rb').read())
data[0x4A] = 2  # header version major byte
open('image_v2.stm32', 'wb').write(data)
"
if "$SIGN_TOOL" -v -k private_key.pem -i image_v2.stm32 -o image_v2.stm32.signed; then
    echo "ERROR: v2 header image should have been rejected"
    exit 1
fi

# test plain key file with password
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -aes-256-cbc -out private_key.pem -pass pass:pa33w0rd
"$SIGN_TOOL" -v -k private_key.pem -p "pa33w0rd" -i image.stm32 -o image.stm32.signed

# test plain key file (brainpool)
openssl ecparam -name brainpoolP256t1 -genkey -out brainpool_private_key.pem
"$SIGN_TOOL" -v -k brainpool_private_key.pem -i image.stm32 -o image.stm32.signed

# test plain key file with password (brainpool)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP256t1 -aes-256-cbc -out brainpool_private_key.pem -pass pass:pa33w0rd
"$SIGN_TOOL" -v -k brainpool_private_key.pem -p "pa33w0rd" -i image.stm32 -o image.stm32.signed

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
"$SIGN_TOOL" -v -k "pkcs11:object=testkeyECp256" -p 12345 -m "$PKCS11_MODULE_PATH" -i image.stm32 -o image.stm32.signed -h hash.bin
"$SIGN_TOOL" -v -k "pkcs11:object=testkeyECp256?pin-value=12345" -m "$PKCS11_MODULE_PATH" -i image.stm32 -o image.stm32.signed -h hash.bin

# Skip for the moment test pkcs11 sign with (brainpoolP256t1)
# will be fixed in later releases: https://github.com/OpenSC/OpenSC/pull/3601
# pkcs11-tool --pin $PIN --module $PKCS11_MODULE_PATH --keypairgen --key-type EC:brainpoolP256t1 --id 2 --label "testkeyECbrainpoolP256t1"
# "$SIGN_TOOL" -v -k "pkcs11:object=testkeyECbrainpoolP256t1" -p 12345 -m "$PKCS11_MODULE_PATH" -i image.stm32 -o image.stm32.signed -h hash.bin
# "$SIGN_TOOL" -v -k "pkcs11:object=testkeyECbrainpoolP256t1?pin-value=12345" -m "$PKCS11_MODULE_PATH" -i image.stm32 -o image.stm32.signed -h hash.bin
