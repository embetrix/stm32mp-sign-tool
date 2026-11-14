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


STM32_BASE_HEADER_FORMAT = '<4s64s11I16s'
STM32_HEADER_VERSION_V2_2 = 0x00020200
STM32_HEADER_SIZE = 512
STM32_PADDING_EXTENSION_TYPE = b'ST\xff\xff'


def generate_stm32_header(magic, checksum, hdr_version, length, entry_addr,
                          rollback_version, option_flags, extensions_length,
                          binary_type):
    base_header = struct.pack(
        STM32_BASE_HEADER_FORMAT,
        magic.encode('ascii'),
        bytes(64),
        checksum,
        hdr_version,
        length,
        entry_addr,
        0,
        0,
        0,
        rollback_version,
        option_flags,
        extensions_length,
        binary_type,
        bytes(16)
    )

    padding_length = STM32_HEADER_SIZE - len(base_header)
    padding_extension = struct.pack(
        f'<4sI{padding_length - 8}x',
        STM32_PADDING_EXTENSION_TYPE,
        padding_length
    )
    return base_header + padding_extension


def generate_stm32_image(output_file, payload):
    checksum = 0
    magic = 'STM2'
    hdr_version = STM32_HEADER_VERSION_V2_2
    length = len(payload)
    entry_addr = 0x08000000
    rollback_version = 0
    option_flags = 1 << 31
    extensions_length = STM32_HEADER_SIZE - struct.calcsize(STM32_BASE_HEADER_FORMAT)
    binary_type = 0x30

    header = generate_stm32_header(
        magic,
        checksum,
        hdr_version,
        length,
        entry_addr,
        rollback_version,
        option_flags,
        extensions_length,
        binary_type
    )

    with open(output_file, 'wb') as output:
        output.write(header + payload)

    print(f'STM32 v2.2 image generated: {output_file}')


def main():
    parser = argparse.ArgumentParser(
        description='Generate an STM32 v2.2 image with a custom header.')
    parser.add_argument('output_file', help='The output file for the STM32 image.')
    parser.add_argument('payload', help='The payload data for the STM32 image.',
                        type=argparse.FileType('rb'))
    args = parser.parse_args()

    generate_stm32_image(args.output_file, args.payload.read())


if __name__ == '__main__':
    main()
