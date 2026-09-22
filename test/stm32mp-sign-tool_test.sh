#!/bin/sh -ex
#
# Copyright (c) 2024
# Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
# 

# The generator scripts live next to this script; the signing tool is picked up
# from the build directory (the working directory used by ctest).
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SIGN_TOOL=${SIGN_TOOL:-$PWD/stm32mp-sign-tool}

dd if=/dev/urandom of=image_unsupported.bin bs=1M count=1 > /dev/null 2>&1

python3 "$SCRIPT_DIR/stm32mp-gen-image.py" image_unsupported.stm32 image_unsupported.bin

openssl ecparam -name prime256v1 -genkey -out private_key_unsupported.pem

# Images with the unsupported v2.3 header version must be rejected.
python3 -c "
data = bytearray(open('image_unsupported.stm32', 'rb').read())
data[0x49] = 3  # header version minor byte
data[0x4A] = 2  # header version major byte
open('image_v2_3.stm32', 'wb').write(data)
"
if "$SIGN_TOOL" -v -k private_key_unsupported.pem \
    -i image_v2_3.stm32 -o image_v2_3.stm32.signed; then
    echo "ERROR: v2.3 header image should have been rejected"
    exit 1
fi
