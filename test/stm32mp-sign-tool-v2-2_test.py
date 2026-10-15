# SPDX-License-Identifier: GPL-3.0-or-later
"""Check v2.2 key tables and authentication, decryption and padding extensions."""
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


# Check the table hash exported by the preceding PKCS#11 signing test.
image = Path("image_v2_2.stm32.signed").read_bytes()
expected = hashlib.sha256(image[212:468]).digest()
actual = Path("hash_v2_2.bin").read_bytes()
assert actual == expected

with tempfile.TemporaryDirectory(prefix="stm32mp-duplicate-keys-") as directory:
    root = Path(directory)
    source = Path("image_v2_2.stm32").resolve()
    private = Path("private_key_v2_2.pem").resolve()
    public = [Path("public_key_v2_2.pem").resolve()]
    public += [Path(f"public_key_v2_2_{index}.pem").resolve() for index in range(1, 8)]
    output = root / "signed.stm32"

    def sign(keys, target=output, index=0):
        arguments = [sign_tool, "-k", str(private), "-p", "pa33w0rd"]
        for key in keys:
            arguments += ["-K", str(key)]
        return run(arguments + ["-x", str(index), "-i", str(source), "-o", str(target)])

    assert sign(public).returncode == 0
    success([verify_tool, str(output)])
    data = output.read_bytes()
    assert len({data[212 + index * 32:244 + index * 32] for index in range(8)}) == 8

    # A valid but different table entry must fail before signing/output.
    target = root / "mismatched.stm32"
    result = sign(public, target, index=3)
    assert result.returncode != 0
    assert "Signing key (-k) does not match public key 3 of the key table (-K/-x)" in result.stderr, result.stderr
    assert not target.exists()

    for length in [0, 1, 31, 32, 33]:
        payload = bytes(range(length))
        alignment_input = root / "alignment.stm32"
        header = bytearray(source.read_bytes()[:512])
        struct.pack_into("<I", header, 68, sum(payload))
        struct.pack_into("<I", header, 76, length)
        alignment_input.write_bytes(header + payload + b"TRAILING")
        target = root / "aligned.stm32"
        arguments = [sign_tool, "-k", str(private), "-p", "pa33w0rd", "-x", "0"]
        for key in public:
            arguments += ["-K", str(key)]
        success(arguments + ["-i", str(alignment_input), "-o", str(target)])
        aligned = target.read_bytes()
        expected_length = (length + 31) // 32 * 32
        assert struct.unpack_from("<I", aligned, 76)[0] == expected_length
        assert aligned[512:] == payload + bytes(expected_length - length) + b"TRAILING"
        success([verify_tool, str(target)])
        success(arguments + ["-i", str(target), "-o", str(alignment_input)])
        assert alignment_input.read_bytes()[68:] == aligned[68:]

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
        hash_end = 512 + struct.unpack_from("<I", image, 76)[0]
        region.write_bytes(image[72:120] + image[128:hash_end])
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

    def verify(image, error=None):
        rejected.write_bytes(image)
        result = run([verify_tool, str(rejected)])
        if error is None:
            assert result.returncode == 0, result.stderr
        else:
            assert result.returncode != 0 and error in result.stderr, result.stderr

    def reject_field(image, offset, value, error):
        malformed = bytearray(image)
        struct.pack_into("<I", malformed, offset, value)
        verify(resign(malformed), error)

    def reject_tampering(image, offset):
        malformed = bytearray(image)
        malformed[offset] ^= 1
        verify(malformed, "Signature does not match")

    # Known limitations: document acceptance until strict validation is added.
    # Bytes beyond the declared payload are not covered by the signature.
    verify(data + b"TRAILING")
    # Signing must preserve trailing bytes without changing the declared length.
    original_source = source
    source = root / "trailing.stm32"
    source.write_bytes(original_source.read_bytes() + b"TRAILING")
    result = sign(public)
    assert result.returncode == 0, result.stderr
    trailing = output.read_bytes()
    verify(trailing)
    assert trailing[512:] == source.read_bytes()[512:]
    assert trailing[76:80] == data[76:80]
    source = original_source
    # The first eight base-padding bytes are signed; zero values are not validated.
    malformed = bytearray(data)
    malformed[112] = 1
    verify(resign(malformed))
    for offset in [112, 119]:
        reject_tampering(data, offset)
    # The last eight base-padding bytes remain in the image but are not signed.
    for offset in [120, 127]:
        malformed = bytearray(data)
        malformed[offset] = 0xa5
        verify(malformed)

    # Authentication: valid layout plus seven focused rejection cases.
    verify(data)
    assert struct.unpack_from("<4s4I", data, 128) == (b"ST\x00\x02", 340, 0, 8, 1)
    for offset, value, error in [
        (128, 0, "Invalid authentication extension type"),
        (132, 339, "Invalid authentication extension length"),
        (136, 8, "Invalid public key index"),
        (140, 7, "Invalid public key count"),
        (100, 0x80000000, "does not contain an authentication extension"),
        (136, 7, "Selected public key does not match its public key hash"),
    ]:
        reject_field(data, offset, value, error)
    reject_tampering(data, 436)

    # Decryption metadata: build an unsigned fixture with the existing payload.
    # This tests extension handling, not actual payload encryption/decryption.
    image = bytearray(source.read_bytes())
    metadata = struct.pack("<4sIII16s", b"ST\x00\x01", 32, 128,
                           0x12345678, hashlib.sha256(image[512:]).digest()[:16])
    struct.pack_into("<I", image, 100, 0x80000002)
    image[128:160] = metadata
    image[160:512] = struct.pack("<4sI344x", b"ST\xff\xff", 352)
    source = root / "extensions.stm32"
    source.write_bytes(image)
    result = sign(public)
    assert result.returncode == 0, result.stderr
    with_decryption = output.read_bytes()

    # Decryption: valid metadata, three bad fields, two tamper cases, re-signing.
    verify(with_decryption)
    assert with_decryption[468:500] == metadata
    assert with_decryption[512:] == image[512:]
    assert struct.unpack_from("<I", with_decryption, 100)[0] == 0x80000003
    for offset, value, error in [
        (468, 0, "Invalid decryption extension type"),
        (472, 31, "Invalid decryption extension length"),
        (476, 256, "Invalid decryption key size"),
    ]:
        reject_field(with_decryption, offset, value, error)
    for offset in [480, 484]:
        reject_tampering(with_decryption, offset)
    source.write_bytes(with_decryption)
    result = sign(public)
    assert result.returncode == 0, result.stderr
    repacked = output.read_bytes()
    verify(repacked)
    assert repacked[68:] == with_decryption[68:]

    # Padding: both valid sizes, four bad fields, and signature protection.
    for image, offset in [(data, 468), (with_decryption, 500)]:
        verify(image)
        assert struct.unpack_from("<4sI", image, offset) == (b"ST\xff\xff", 512 - offset)
        assert image[offset + 8:512] == bytes(504 - offset)
    for offset, value, error in [
        (100, 1, "does not have header padding enabled"),
        (468, 0, "Invalid padding extension type"),
        (472, 43, "Invalid padding extension length"),
        (104, 383, "Invalid header extensions length"),
    ]:
        reject_field(data, offset, value, error)
    reject_tampering(data, 476)

print("v2.2 duplicate keys and authentication/decryption/padding extensions: PASS")
