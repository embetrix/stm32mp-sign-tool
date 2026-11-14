#!/bin/sh -ex
#
# Copyright (c) 2024
# Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
#

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SIGN_TOOL=${SIGN_TOOL:-$PWD/stm32mp-sign-tool}
VERIFY_TOOL=${VERIFY_TOOL:-$PWD/stm32mp-verify-test}

dd if=/dev/urandom of=image_v2_2.bin bs=1M count=1 > /dev/null 2>&1

python3 "$SCRIPT_DIR/stm32mp-gen-image-v2-2.py" image_v2_2.stm32 image_v2_2.bin

# Seven distinct companion keys for each curve; slot zero is generated below.
for index in 1 2 3 4 5 6 7; do
    openssl ecparam -name prime256v1 -genkey -out "companion_v2_2_$index.pem"
    openssl pkey -in "companion_v2_2_$index.pem" -pubout -out "public_key_v2_2_$index.pem"
    openssl ecparam -name brainpoolP256t1 -genkey -out "companion_brainpool_v2_2_$index.pem"
    openssl pkey -in "companion_brainpool_v2_2_$index.pem" -pubout -out "brainpool_public_key_v2_2_$index.pem"
done

# test plain key file
openssl ecparam -name prime256v1 -genkey -out private_key_v2_2.pem
openssl pkey -in private_key_v2_2.pem -pubout -out public_key_v2_2.pem
"$SIGN_TOOL" -v -k private_key_v2_2.pem \
    -K public_key_v2_2.pem -K public_key_v2_2_1.pem \
    -K public_key_v2_2_2.pem -K public_key_v2_2_3.pem \
    -K public_key_v2_2_4.pem -K public_key_v2_2_5.pem \
    -K public_key_v2_2_6.pem -K public_key_v2_2_7.pem -x 0 \
    -i image_v2_2.stm32 -o image_v2_2.stm32.signed

# test plain key file with password
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -aes-256-cbc \
    -out private_key_v2_2.pem -pass pass:pa33w0rd
openssl pkey -in private_key_v2_2.pem -passin pass:pa33w0rd \
    -pubout -out public_key_v2_2.pem
"$SIGN_TOOL" -v -k private_key_v2_2.pem -p "pa33w0rd" \
    -K public_key_v2_2.pem -K public_key_v2_2_1.pem \
    -K public_key_v2_2_2.pem -K public_key_v2_2_3.pem \
    -K public_key_v2_2_4.pem -K public_key_v2_2_5.pem \
    -K public_key_v2_2_6.pem -K public_key_v2_2_7.pem -x 0 \
    -i image_v2_2.stm32 -o image_v2_2.stm32.signed

# test plain key file (brainpool)
openssl ecparam -name brainpoolP256t1 -genkey -out brainpool_private_key_v2_2.pem
openssl pkey -in brainpool_private_key_v2_2.pem \
    -pubout -out brainpool_public_key_v2_2.pem
"$SIGN_TOOL" -v -k brainpool_private_key_v2_2.pem \
    -K brainpool_public_key_v2_2.pem -K brainpool_public_key_v2_2_1.pem \
    -K brainpool_public_key_v2_2_2.pem -K brainpool_public_key_v2_2_3.pem \
    -K brainpool_public_key_v2_2_4.pem -K brainpool_public_key_v2_2_5.pem \
    -K brainpool_public_key_v2_2_6.pem -K brainpool_public_key_v2_2_7.pem -x 0 \
    -i image_v2_2.stm32 -o image_v2_2.stm32.signed

# test plain key file with password (brainpool)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP256t1 \
    -aes-256-cbc -out brainpool_private_key_v2_2.pem -pass pass:pa33w0rd
openssl pkey -in brainpool_private_key_v2_2.pem -passin pass:pa33w0rd \
    -pubout -out brainpool_public_key_v2_2.pem
"$SIGN_TOOL" -v -k brainpool_private_key_v2_2.pem -p "pa33w0rd" \
    -K brainpool_public_key_v2_2.pem -K brainpool_public_key_v2_2_1.pem \
    -K brainpool_public_key_v2_2_2.pem -K brainpool_public_key_v2_2_3.pem \
    -K brainpool_public_key_v2_2_4.pem -K brainpool_public_key_v2_2_5.pem \
    -K brainpool_public_key_v2_2_6.pem -K brainpool_public_key_v2_2_7.pem -x 0 \
    -i image_v2_2.stm32 -o image_v2_2.stm32.signed

# test pkcs11 key
export PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so
export PIN="12345"
export SO_PIN="1234"
export SOFTHSM2_CONF=$PWD/.softhsm-v2-2/softhsm2.conf
export TOKEN_NAME="token-v2-2"

mkdir -p .softhsm-v2-2/tokens
echo "directories.tokendir = $PWD/.softhsm-v2-2/tokens" > .softhsm-v2-2/softhsm2.conf
pkcs11-tool --pin $PIN --module $PKCS11_MODULE_PATH --slot-index=0 \
    --init-token --label=$TOKEN_NAME --so-pin $SO_PIN --init-pin
pkcs11-tool --pin $PIN --module $PKCS11_MODULE_PATH --keypairgen \
    --key-type EC:prime256v1 --id 1 --label "testkeyECp256V22"

for index in 1 2 3 4 5 6 7; do
    pkcs11-tool --pin "$PIN" --module "$PKCS11_MODULE_PATH" --keypairgen \
        --key-type EC:prime256v1 --id "$((index + 1))" --label "testkeyECp256V22-$index"
done

PUBLIC_KEY_URI="pkcs11:object=testkeyECp256V22;type=public"
"$SIGN_TOOL" -v -k "pkcs11:object=testkeyECp256V22" -p 12345 \
    -m "$PKCS11_MODULE_PATH" \
    -K "$PUBLIC_KEY_URI" -K "pkcs11:object=testkeyECp256V22-1;type=public" \
    -K "pkcs11:object=testkeyECp256V22-2;type=public" -K "pkcs11:object=testkeyECp256V22-3;type=public" \
    -K "pkcs11:object=testkeyECp256V22-4;type=public" -K "pkcs11:object=testkeyECp256V22-5;type=public" \
    -K "pkcs11:object=testkeyECp256V22-6;type=public" -K "pkcs11:object=testkeyECp256V22-7;type=public" -x 0 \
    -i image_v2_2.stm32 -o image_v2_2.stm32.signed -h hash_v2_2.bin
"$SIGN_TOOL" -v -k "pkcs11:object=testkeyECp256V22?pin-value=12345" \
    -m "$PKCS11_MODULE_PATH" \
    -K "$PUBLIC_KEY_URI" -K "pkcs11:object=testkeyECp256V22-1;type=public" \
    -K "pkcs11:object=testkeyECp256V22-2;type=public" -K "pkcs11:object=testkeyECp256V22-3;type=public" \
    -K "pkcs11:object=testkeyECp256V22-4;type=public" -K "pkcs11:object=testkeyECp256V22-5;type=public" \
    -K "pkcs11:object=testkeyECp256V22-6;type=public" -K "pkcs11:object=testkeyECp256V22-7;type=public" -x 0 \
    -i image_v2_2.stm32 -o image_v2_2.stm32.signed -h hash_v2_2.bin

# Skip for the moment test pkcs11 sign with (brainpoolP256t1)
# will be fixed in later releases: https://github.com/OpenSC/OpenSC/pull/3601

# Duplicate keys and authentication/decryption/padding extension checks.
python3 "$SCRIPT_DIR/stm32mp-sign-tool-v2-2_test.py" "$SIGN_TOOL" "$VERIFY_TOOL"
