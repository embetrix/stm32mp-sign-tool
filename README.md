# STM32MP Sign Tool

## Overview

The `stm32mp-sign-tool` is a utility for signing and verifying firmware images for STM32MP MPUs. 
It uses ECDSA (Elliptic Curve Digital Signature Algorithm) to ensure the integrity and authenticity of the firmware.

This tool is reverse-engineered from the official STM32 signing tool available at [STM32 Signing Tool](https://wiki.st.com/stm32mpu/wiki/Signing_tool).

**Note:** This tool does not implement all the functionalities of the official ST Tools and should be used with care.

## Features

- Sign firmware images with ECDSA.
- Verify the signature of firmware images.
- Compatible with STM32 MPU firmware headers.

## Requirements

- OpenSSL library
- C++ compiler
- CMake
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

## Usage

### Sign a Firmware Image

Generate a ECDSA key:

```sh
openssl ecparam -name prime256v1 -genkey -out <private_key.pem>
```
Sign a firmware image, use the following command:

```sh
./stm32mp-sign-tool -k <private_key_file> -i <image.stm32> -o <image.stm32.signed>
```

### Sign a Firmware Image using a HSM Token

Generate a ECDSA key:

```sh
pkcs11-tool --pin <pin> --module <Module Path> --keypairgen --key-type EC:prime256v1 --id <KeyID> --label <KeyLabel>
```

Sign a firmware image, use the URI of the key:

```sh
./stm32mp-sign-tool -v -k  "pkcs11:object=<KeyLabel>" -p <pin> -i <image.stm32> -o <image.stm32.signed>
```

## License

This project is licensed under the terms of the **GNU General Public License v3 (GPLv3)**.
You are free to use, modify, and distribute this software under the conditions outlined in the GPLv3 license.

For more information about the GPLv3 license, refer to the [LICENSE](LICENSE) file in this repository or visit [GNU's official page](https://www.gnu.org/licenses/gpl-3.0.html).

---

## Implicit Contributor License Agreement (CLA)

By submitting a pull request to this repository, you agree to the following terms:

1. You certify that your contribution is your original work or that you have the necessary rights to submit it.
2. You grant the project maintainers a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to:
   - Use, modify, sublicense, and distribute your contribution under the terms of the **GPLv3**.
   - Use, modify, sublicense, and distribute your contribution under alternative licenses, including commercial licenses.
3. You understand that you retain the copyright to your contribution but agree it may be relicensed under these terms.

---