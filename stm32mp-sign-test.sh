#!/bin/bash -e


dd if=/dev/urandom of=image.bin bs=1M count=1 > /dev/null 2>&1

python3 stm32mp-gen-image.py image.stm32 image.bin

openssl ecparam -name prime256v1 -genkey -out private_key.pem
openssl ec -in private_key.pem -pubout -out public_key.pem

./stm32mp-sign-tool -v -k  private_key.pem -i image.stm32 -o image.stm32.signed
