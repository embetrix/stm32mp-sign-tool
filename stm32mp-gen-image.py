#
#  (C) Copyright 2024
#  Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
# 
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License as
#  published by the Free Software Foundation; version 3 of
#  the License.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston,
#  MA 02111-1307 USA
#

import struct
import argparse

# Define the STM32 header format
STM32_HEADER_FORMAT = '<4s64s10I64s83xB'

def generate_stm32_header(magic, checksum, hdr_version, length, entry_addr, load_addr, rollback_version, option_flags, ecdsa_algo):
    # Pack the header fields into a binary format
    header = struct.pack(
        STM32_HEADER_FORMAT,
        magic.encode('ascii'),
        bytes(64),  # Empty signature
        checksum,
        hdr_version,
        length,
        entry_addr,
        0,  # reserved1
        load_addr,
        0,  # reserved2
        rollback_version,
        option_flags,
        ecdsa_algo,
        bytes(64),  # Empty public key
        0  # last_byte
    )
    return header

def generate_stm32_image(output_file, payload):
    # Calculate the checksum (for simplicity, using a dummy value)
    checksum = 0

    # Define other header fields
    magic = 'STM2'
    hdr_version = 1
    length = len(payload)
    entry_addr = 0x08000000
    load_addr = 0x08000000
    rollback_version = 0
    option_flags = 0
    ecdsa_algo = 1  # Assuming NIST256p

    # Generate the STM32 header
    header = generate_stm32_header(
        magic,
        checksum,
        hdr_version,
        length,
        entry_addr,
        load_addr,
        rollback_version,
        option_flags,
        ecdsa_algo
    )

    # Concatenate the header and payload to form the STM32 image
    stm32_image = header + payload

    # Write the STM32 image to the output file
    with open(output_file, 'wb') as f:
        f.write(stm32_image)

    print(f'STM32 image generated: {output_file}')

def main():
    parser = argparse.ArgumentParser(description='Generate an STM32 image with a custom header.')
    parser.add_argument('output_file', help='The output file for the STM32 image.')
    parser.add_argument('payload', help='The payload data for the STM32 image.', type=argparse.FileType('rb'))

    args = parser.parse_args()

    payload = args.payload.read()
    generate_stm32_image(args.output_file, payload)

if __name__ == '__main__':
    main()