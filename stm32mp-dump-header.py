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
STM32_HEADER_FORMAT = '<4s64s10I64s83sB'  # Matches the provided C struct layout
STM32_HEADER_SIZE = struct.calcsize(STM32_HEADER_FORMAT)  # Calculate header size

def unpack_stm32_header(header):
    """
    Unpacks the STM32Header binary data into a dictionary.
    """
    try:
        unpacked_header = struct.unpack(STM32_HEADER_FORMAT, header)
    except struct.error as e:
        print(f"Error unpacking header: {e}")
        print(f"Header length: {len(header)}")
        print(f"Expected length: {STM32_HEADER_SIZE}")
        return None

    # Create a dictionary with unpacked fields
    header_dict = {
        'magic': unpacked_header[0].decode('ascii').strip('\x00'),
        'signature': unpacked_header[1],
        'checksum': unpacked_header[2],
        'hdr_version': unpacked_header[3],
        'length': unpacked_header[4],
        'entry_addr': unpacked_header[5],
        'reserved1': unpacked_header[6],
        'load_addr': unpacked_header[7],
        'reserved2': unpacked_header[8],
        'rollback_version': unpacked_header[9],
        'option_flags': unpacked_header[10],
        'ecdsa_algo': unpacked_header[11],
        'ecdsa_pubkey': unpacked_header[12],
        'padding': unpacked_header[13],
        'binary_type': unpacked_header[14],
    }
    return header_dict

def dump_stm32_header(header_dict):
    """
    Prints the STM32Header fields in a human-readable format.
    """
    print("STM32 Header:")
    for key, value in header_dict.items():
        if isinstance(value, bytes):
            value = value.hex()  # Convert bytes to hex for display
        print(f"{key}: {value}")

def main():
    parser = argparse.ArgumentParser(description='Dump STM32 header information from a binary image.')
    parser.add_argument('input_file', help='Input STM32 image file')
    args = parser.parse_args()

    # Read the binary file and extract the header
    with open(args.input_file, 'rb') as f:
        header = f.read(STM32_HEADER_SIZE)

    if len(header) < STM32_HEADER_SIZE:
        print(f"Error: File contains only {len(header)} bytes, expected {STM32_HEADER_SIZE} bytes.")
        return

    # Unpack and dump the STM32 header
    header_dict = unpack_stm32_header(header)
    if header_dict:
        dump_stm32_header(header_dict)
    else:
        print("Failed to unpack STM32 header.")

if __name__ == '__main__':
    main()
