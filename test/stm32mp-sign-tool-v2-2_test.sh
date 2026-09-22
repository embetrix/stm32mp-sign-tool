#!/bin/sh -ex
#
# Copyright (c) 2024
# Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
#

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SIGN_TOOL=${SIGN_TOOL:-$PWD/stm32mp-sign-tool}

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

python3 -c "
import hashlib
image = open('image_v2_2.stm32.signed', 'rb').read()
expected = hashlib.sha256(image[212:468]).digest()
actual = open('hash_v2_2.bin', 'rb').read()
assert actual == expected
"

# Skip for the moment test pkcs11 sign with (brainpoolP256t1)
# will be fixed in later releases: https://github.com/OpenSC/OpenSC/pull/3601

# The CLI only signs. Build the small verification driver here to keep all
# v2.2 tests in this script; generated artifacts stay in the build directory.
"${CXX:-c++}" -std=c++17 -I "$SCRIPT_DIR/../src" -x c++ - \
    "$SCRIPT_DIR/../src/stm32-image-format-v2-2.cpp" \
    "$SCRIPT_DIR/../src/openssl-keys.cpp" "$SCRIPT_DIR/../src/logger.cpp" \
    -lcrypto -o stm32mp-verify-test <<'CPP'
// SPDX-License-Identifier: GPL-3.0-or-later
#include "logger.hpp"
#include "openssl-keys.hpp"
#include "stm32-image-format-v2-2.hpp"

#include <array>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

// Test driver for verification, which is not exposed by the production CLI.
int main(int argc, char* argv[]) {
    if (argc != 2) {
        return 2;
    }
    std::ifstream input(argv[1], std::ios::binary);
    if (!input) {
        return 2;
    }
    const std::vector<unsigned char> image((std::istreambuf_iterator<char>(input)), {});
    STM32ImageFormatV2_2 format(std::make_shared<OpenSslKeys>(),
                               std::make_shared<Logger>(),
                               std::array<std::string, 8>{}, 0);
    return format.verify(image) == 0 ? 0 : 1;
}
CPP

# Duplicate keys and authentication/decryption/padding extension checks.
python3 - "$SIGN_TOOL" "$PWD/stm32mp-verify-test" <<'PYTHON'
from pathlib import Path
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile

sign_tool, verify_tool = map(lambda value: str(Path(value).resolve()), sys.argv[1:])


def run(arguments):
    return subprocess.run(arguments, capture_output=True, text=True, check=False)


def success(arguments):
    result = run(arguments)
    assert result.returncode == 0, result.stderr
    return result


with tempfile.TemporaryDirectory(prefix="stm32mp-duplicate-keys-") as directory:
    root = Path(directory)
    source = Path("image_v2_2.stm32").resolve()
    private = Path("private_key_v2_2.pem").resolve()
    public = [Path("public_key_v2_2.pem").resolve()]
    public += [Path(f"public_key_v2_2_{index}.pem").resolve() for index in range(1, 8)]
    output = root / "signed.stm32"

    def sign(keys, target=output):
        arguments = [sign_tool, "-k", str(private), "-p", "pa33w0rd"]
        for key in keys:
            arguments += ["-K", str(key)]
        return run(arguments + ["-x", "0", "-i", str(source), "-o", str(target)])

    assert sign(public).returncode == 0
    success([verify_tool, str(output)])
    data = output.read_bytes()
    assert len({data[212 + index * 32:244 + index * 32] for index in range(8)}) == 8

    copied = root / "copied-public.pem"
    shutil.copyfile(public[0], copied)
    # Different PEM encoding, same EC key material.
    encoded = root / "reencoded-public.pem"
    success(["openssl", "ec", "-pubin", "-in", str(public[0]),
             "-param_enc", "explicit", "-pubout", "-out", str(encoded)])
    for duplicate in [public[0], copied, encoded]:
        keys = public.copy()
        keys[7] = duplicate
        target = root / "rejected.stm32"
        result = sign(keys, target)
        assert result.returncode != 0
        assert "Duplicate public keys at indices 0 and 7" in result.stderr, result.stderr
        assert not target.exists()

    def export_hash(keys, target):
        arguments = [sign_tool, "-k", str(private), "-m", os.environ["PKCS11_MODULE_PATH"]]
        for key in keys:
            arguments += ["-K", str(key)]
        return run(arguments + ["-x", "0", "-h", str(target)])

    hash_output = root / "table-hash.bin"
    result = export_hash(public, hash_output)
    assert result.returncode == 0, result.stderr
    assert hash_output.read_bytes() == hashlib.sha256(data[212:468]).digest()
    for duplicate in [public[0], copied, encoded]:
        keys = public.copy()
        keys[7] = duplicate
        target = root / "rejected-hash.bin"
        result = export_hash(keys, target)
        assert result.returncode != 0
        assert "Duplicate public keys at indices 0 and 7" in result.stderr, result.stderr
        assert not target.exists()

    # Different PKCS#11 URIs resolving to the same token public key.
    token_keys = ["pkcs11:object=testkeyECp256V22;type=public"]
    token_keys += [f"pkcs11:object=testkeyECp256V22-{index};type=public" for index in range(1, 8)]
    token_keys[7] = "pkcs11:object=testkeyECp256V22;type=public;id=%01"
    result = export_hash(token_keys, root / "rejected-token-hash.bin")
    assert result.returncode != 0
    assert "Duplicate public keys at indices 0 and 7" in result.stderr, result.stderr

    def resign(image):
        image = bytearray(image)
        region = root / "region.bin"
        region.write_bytes(image[72:])
        der = root / "signature.der"
        success(["openssl", "dgst", "-sha256", "-sign", str(private),
                 "-passin", "pass:pa33w0rd", "-out", str(der), str(region)])
        success(["openssl", "dgst", "-sha256", "-verify", str(public[0]),
                 "-signature", str(der), str(region)])
        signature = der.read_bytes()
        position = 2
        scalars = []
        for _ in range(2):
            assert signature[position] == 2
            length = signature[position + 1]
            scalar = int.from_bytes(signature[position + 2:position + 2 + length], "big")
            scalars.append(scalar.to_bytes(32, "big"))
            position += 2 + length
        image[4:68] = b"".join(scalars)
        return image

    # Duplicate non-selected entries and re-sign: rejection must come from the
    # table check rather than a broken signature or selected-key hash mismatch.
    malformed = bytearray(data)
    malformed[436:468] = malformed[244:276]
    malformed = resign(malformed)
    rejected = root / "duplicate-table.stm32"
    rejected.write_bytes(malformed)
    result = run([verify_tool, str(rejected)])
    assert result.returncode != 0
    assert "Duplicate public keys at indices 1 and 7" in result.stderr, result.stderr

    # Exercise both layouts and curves using the existing image and PEM keys.
    for curve in ["", "brainpool_"]:
        private = Path(f"{curve}private_key_v2_2.pem").resolve()
        public = [Path(f"{curve}public_key_v2_2.pem").resolve()]
        public += [Path(f"{curve}public_key_v2_2_{i}.pem").resolve() for i in range(1, 8)]
        for decrypt in [False, True]:
            image = bytearray(Path("image_v2_2.stm32").read_bytes())
            metadata = struct.pack("<4sIII16s", b"ST\x00\x01", 32, 128,
                                   0x12345678, hashlib.sha256(image[512:]).digest()[:16])
            if decrypt:
                struct.pack_into("<I", image, 100, 0x80000002)
                image[128:160] = metadata
                image[160:512] = struct.pack("<4sI344x", b"ST\xff\xff", 352)
            source = root / "extensions.stm32"
            source.write_bytes(image)
            result = sign(public)
            assert result.returncode == 0, result.stderr
            data = output.read_bytes()
            success([verify_tool, str(output)])
            assert data[512:] == image[512:]
            assert struct.unpack_from("<4s4I", data, 128) == (
                b"ST\x00\x02", 340, 0, 8, 2 if curve else 1)
            assert len({data[212 + i * 32:244 + i * 32] for i in range(8)}) == 8
            assert struct.unpack_from("<2I", data, 100) == (0x80000001 | (2 if decrypt else 0), 384)
            padding = 500 if decrypt else 468
            if decrypt:
                assert data[468:500] == metadata
            assert struct.unpack_from("<4sI", data, padding) == (b"ST\xff\xff", 512 - padding)
            assert data[padding + 8:512] == bytes(504 - padding)

            # Re-signing must preserve all extension fields and the payload.
            source.write_bytes(data)
            assert sign(public).returncode == 0
            assert output.read_bytes()[68:] == data[68:]
            success([verify_tool, str(output)])

            # Re-sign bad fields so rejection tests structural validation.
            fields = [(128, 0, "Invalid authentication extension type"),
                      (132, 339, "Invalid authentication extension length"),
                      (136, 8, "Invalid public key index"),
                      (140, 7, "Invalid public key count"),
                      (padding, 0, "Invalid padding extension type"),
                      (padding + 4, 0, "Invalid padding extension length"),
                      (104, 383, "Invalid header extensions length")]
            if decrypt:
                fields += [(468, 0, "Invalid decryption extension type"),
                           (472, 31, "Invalid decryption extension length"),
                           (476, 256, "Invalid decryption key size")]
            for offset, value, error in fields:
                malformed = bytearray(data)
                struct.pack_into("<I", malformed, offset, value)
                rejected.write_bytes(resign(malformed))
                result = run([verify_tool, str(rejected)])
                assert result.returncode != 0 and error in result.stderr, result.stderr
            # Metadata and padding are protected by the image signature.
            for offset in ([480, 484, padding + 8] if decrypt else [padding + 8]):
                malformed = bytearray(data)
                malformed[offset] ^= 1
                rejected.write_bytes(malformed)
                result = run([verify_tool, str(rejected)])
                assert result.returncode != 0 and "Signature does not match" in result.stderr, result.stderr

print("v2.2 duplicate keys and authentication/decryption/padding extensions: PASS")
PYTHON
