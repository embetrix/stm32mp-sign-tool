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
- Support for separate public key usage (private key only needed for signing).
- Two-step signing workflow for external signing (HSM, remote signing, etc.).
- Automatic DER signature format parsing (compatible with OpenSSL output).
- Generate public key hash from either private or public key.
- Currently supports only STM32MP15x MPU firmware image headers.

## Requirements

- C++ compiler
- CMake
- OpenSSL library
- Optional: PKCS#11 libraries and tools for HSM signing

## Installation

### Install Dependencies

#### Ubuntu

```sh
sudo apt-get update
sudo apt-get install -y openssl libssl-dev python3 softhsm2 opensc libengine-pkcs11-openssl
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

Create sha256 to sign from image

```sh
stm32mp-sign-tool -u <public_key_file> -i <image.stm32> -s <image-sha256.bin>
```

Sign image eg. with openssl

```sh
openssl pkeyutl -sign -inkey <private_key_file> -passin pass:<> -in <image-sha256.bin> -out <signature.der>
```

Apply the signature to create the signed image

```sh
stm32mp-sign-tool -u <public_key_file> -i <image.stm32> -d <signature.der> -o <image.stm32.signed>
```

The tool automatically handles both DER-encoded signatures (from OpenSSL) and raw 64-byte signatures.

### Sign a Firmware Image using a HSM Token

Generate an ECDSA key:

```sh
pkcs11-tool --pin <pin> --module <Module Path> --keypairgen --key-type EC:prime256v1 --id <KeyID> --label <KeyLabel>
```

Sign a firmware image using the URI of the key:

```sh
stm32mp-sign-tool -v -k "pkcs11:object=<KeyLabel>" -p <pin> -i <image.stm32> -o <image.stm32.signed>
```

### Generating the public key hashes

From a private key:

```sh
stm32mp-sign-tool -v -k <private_key_file> -h <hash_output>
```

From a public key:

```sh
stm32mp-sign-tool -u <public_key_file> -h <hash_output>
```

Or with PKCS#11:

```sh
stm32mp-sign-tool -k "pkcs11:object=<KeyLabel>" -p <pin> -h <hash_output>
```

## Command Line Options

- `-k` - Private key file or PKCS#11 URI (required for signing)
- `-u` - Public key file
- `-p` - Passphrase or PIN for private key
- `-v` - Verbose mode
- `-i` - Input image file to sign
- `-o` - Output signed image file
- `-h` - Output file for public key hash
- `-s` - Output file for hash to sign
- `-d` - Input signature file

**Note:** The `-d` option accepts both DER-encoded signatures (standard OpenSSL output) and raw 64-byte signatures.

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
