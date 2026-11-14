# stm32mp-sign-tool

![pipeline status](https://github.com/embetrix/stm32mp-sign-tool/actions/workflows/cmake-single-platform.yml/badge.svg)

## Overview

The `stm32mp-sign-tool` is a lightweight open-source alternative to `STM32_SigningTool_CLI` that does not require the full `STM32CubeProgrammer` installation and dependencies. 
It is a utility for signing and verifying firmware images for STM32MP MPUs.
It uses ECDSA (Elliptic Curve Digital Signature Algorithm) to ensure the integrity and authenticity of the firmware used in secure boot process.

**Disclaimer:** This tool is entirely developed based on the [public specification](https://wiki.st.com/stm32mpu/wiki/STM32_header_for_binary_files) of the STM32 header format. It does not use reverse engineering or incorporate any proprietary code. Additionally, it does not implement all the functionalities of the [official ST Tools](https://wiki.st.com/stm32mpu/wiki/Signing_tool). Use this utility with care, as it is not affiliated with nor endorsed by STMicroelectronics.

## Features

- Sign/Verify firmware images with ECDSA (NIST P-256 or brainpool 256).
- Support for HSM Token (PKCS#11).
- Detects the [STM32 header version](https://wiki.st.com/stm32mpu/wiki/STM32_header_for_binary_files) of the firmware image.
- Supports header v1 (STM32MP15x) and v2.2 (STM32MP23x and STM32MP25x).
- Header v2.0 (STM32MP13x) and v2.3 (STM32MP21x) are detected but remain unsupported.
- v2.2 signing requires eight distinct public keys and a selected key index; verification uses the authentication data embedded in the image. Signing automatically verifies its result; the CLI does not expose a standalone verification command.

## Requirements

- C++ compiler
- CMake
- OpenSSL library (>= 3.0)
- Optional: PKCS#11 provider and tools for HSM signing

## Installation

### Install Dependencies

#### Ubuntu

```sh
sudo apt-get update
sudo apt-get install -y openssl libssl-dev python3 softhsm2 opensc pkcs11-provider
```

## Build

```sh
cmake .
make
```

## Test

```sh
ctest -V
```

## Install

```sh
sudo make install
```

## Usage

### Sign a Firmware Image

Generate an ECDSA key:

```sh
openssl ecparam -name prime256v1 -genkey -out <private_key.pem>
```

Sign a firmware image using the following command:

```sh
stm32mp-sign-tool -k <private_key_file> -i <image.stm32> -o <image.stm32.signed>
```

### Sign a v2.2 Firmware Image

The single-key signing example above applies to v1. For v2.2, supply exactly eight distinct public keys using eight `-K` options, in table order. Use `-x` to select an index from `0` to `7`. The private key supplied with `-k` must match the selected public key. Duplicate public keys are rejected.

Sign an existing v2.2 image with the key at index `3` and export its public-key table hash:

```sh
stm32mp-sign-tool -k private_key_3.pem \
    -K public_key_0.pem -K public_key_1.pem \
    -K public_key_2.pem -K public_key_3.pem \
    -K public_key_4.pem -K public_key_5.pem \
    -K public_key_6.pem -K public_key_7.pem -x 3 \
    -i image_v2_2.stm32 -o signed_image_v2_2.stm32 -h public_key_table_hash.bin
```

Add `-p <passphrase>` when using an encrypted private key. Omitting `-p` leaves password prompting to OpenSSL; `-p ""` explicitly supplies an empty password.

Signing rebuilds the authentication extension and normalizes the padding flag, extension length, and padding type. Existing decryption metadata is preserved; the tool does not encrypt or decrypt the payload.

For `-o`, missing parent directories are created recursively. If no `-o` is supplied, signing and verification happen in memory and no signed image is saved. Trailing bytes beyond the declared payload remain in the output; verification warns that they are not authenticated.

### Sign a Firmware Image using a HSM Token

Generate an ECDSA key:

```sh
pkcs11-tool --pin <pin> --module <Module Path> --keypairgen --key-type EC:prime256v1 --id <KeyID> --label <KeyLabel>
```

Sign a firmware image using the URI of the key:

```sh
stm32mp-sign-tool -v -k "pkcs11:object=<KeyLabel>" [-m <Module Path>] -p <pin> -i <image.stm32> -o <image.stm32.signed>
```

For v2.2 HSM signing, also supply eight `-K` public-key descriptors and `-x`, as in the v2.2 example. Both `-k` and `-K` accept PKCS#11 URIs. The selected public key must match the private signing key on the token. For v1 images, `-K` and `-x` are ignored with a warning.

### Generating the public key hashes

```sh
stm32mp-sign-tool -v -k <private_key_file> -h <hash output>
```
or

```sh
stm32mp-sign-tool -v -k "pkcs11:object=<KeyLabel>" -p <pin> -h <hash output>
```


### v2.2 Public-Key Table Hash

The single-key hash commands above export `SHA256(public_key)` for v1. With a v2.2 input, `-h` instead exports the 32-byte hash of the eight-entry public-key hash table:

To export the table hash without signing an image, omit `-i` and supply the eight public keys and index:

```sh
stm32mp-sign-tool -k private_key_0.pem \
    -K public_key_0.pem -K public_key_1.pem \
    -K public_key_2.pem -K public_key_3.pem \
    -K public_key_4.pem -K public_key_5.pem \
    -K public_key_6.pem -K public_key_7.pem -x 0 \
    -h public_key_table_hash.bin
```

The CLI still requires `-k` and `-x` for this command, although table-hash generation only loads the public keys. Keep the public keys in the same order used to calculate the device's provisioned OTP table hash; changing a key or its position changes the resulting hash.


## License

This project is licensed under the terms of the **GNU General Public License v3 (GPLv3)**. You are free to use, modify, and distribute this software under the conditions outlined in the GPLv3 license.

For more information about the GPLv3 license, refer to the [LICENSE](LICENSE) file in this repository or visit [GNU's official page](https://www.gnu.org/licenses/gpl-3.0.html).

## Contributor License Agreement (CLA)

By submitting a pull request to this repository, you agree to the following terms:

1. You certify that your contribution is your original work or that you have the necessary rights to submit it.
2. You grant the project maintainers a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to:
   - Use, modify, sublicense, and distribute your contribution under the terms of the **GPLv3**.
   - Use, modify, sublicense, and distribute your contribution under alternative licenses, including commercial licenses.
3. You understand that you retain the copyright to your contribution but agree it may be relicensed under these terms.
