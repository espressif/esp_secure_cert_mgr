#!/usr/bin/env python3
"""
Enhanced TLV Format Generator using Construct Library
Provides improved readability, endianness handling, and custom TLV support
"""

import enum
import csv
import os
import sys
import io
import zlib
import struct
import base64
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Tuple, Any, Optional, Union
from construct import (Struct, Int32ul, Int8ul, Int16ul, Int32sl, Bytes, this)
from pathlib import Path

from esp_secure_cert.esp_secure_cert_helper import (
    load_private_key,
    load_certificate,
    get_efuse_key_file,
)
from cryptography.hazmat.primitives import serialization
from esp_secure_cert import configure_ds, tlv_format, tlv_parser
from esp_secure_cert.tlv_format import tlv_type_t, tlv_priv_key_type_t



class TlvSubtype(enum.IntEnum):
    SUBTYPE_0 = 0
    SUBTYPE_1 = 1
    SUBTYPE_2 = 2
    SUBTYPE_3 = 3
    SUBTYPE_4 = 4
    SUBTYPE_5 = 5
    SUBTYPE_MAX = 254
    SUBTYPE_INVALID = 255




# Constants
MIN_ALIGNMENT_REQUIRED = 16
TLV_MAGIC = 0xBA5EBA11
PARTITION_SIZE = 0x2000  # 8KB
MAGIC_END = 0xFFFF

esp_secure_cert_data_dir = 'esp_secure_cert_data'
# hmac_key_file is generated when HMAC_KEY is calculated,
# it is used when burning HMAC_KEY to efuse
hmac_key_file = os.path.join(esp_secure_cert_data_dir, 'hmac_key.bin')
ecdsa_key_file = os.path.join(esp_secure_cert_data_dir, 'ecdsa_key.bin')
# csv and bin filenames are default filenames
# for nvs partition files created with this script
csv_filename = os.path.join(esp_secure_cert_data_dir, 'esp_secure_cert.csv')
bin_filename = os.path.join(esp_secure_cert_data_dir, 'esp_secure_cert.bin')

# Construct structures with proper endianness
TlvHeader = Struct(
    "magic" / Int32ul,  # Little-endian 32-bit unsigned int
    "flags" / Int8ul,   # 8-bit flags
    "reserved" / Bytes(3),  # 3 reserved bytes
    "type" / Int8ul,    # TLV type
    "subtype" / Int8ul, # TLV subtype
    "length" / Int16ul, # Little-endian 16-bit length
)

TlvFooter = Struct(
    "crc" / Int32ul,    # Little-endian 32-bit CRC
)

TlvEntry = Struct(
    "header" / TlvHeader,
    "data" / Bytes(this.header.length),
    "padding" / Bytes(lambda ctx: _calculate_padding(ctx.header.length)),
    "footer" / TlvFooter,
)

def _calculate_padding(data_length: int) -> int:
    """Calculate padding needed for 16-byte alignment"""
    return (MIN_ALIGNMENT_REQUIRED - (data_length % MIN_ALIGNMENT_REQUIRED)) % MIN_ALIGNMENT_REQUIRED


def _get_flag_byte(key_type: tlv_priv_key_type_t) -> int:
    """Generate flag byte based on private key type"""
    flags = 0
    if key_type == tlv_priv_key_type_t.ESP_SECURE_CERT_HMAC_ENCRYPTED_KEY:
        flags |= (1 << 7)  # bit 7
    elif key_type == tlv_priv_key_type_t.ESP_SECURE_CERT_HMAC_DERIVED_ECDSA_KEY:
        flags |= (1 << 6)  # bit 6
    elif key_type == tlv_priv_key_type_t.ESP_SECURE_CERT_ECDSA_PERIPHERAL_KEY:
        flags |= (1 << 3)  # bit 3
    return flags

class TlvPartitionBuilder:
    """Builder class for creating TLV partitions with custom data support"""

    def __init__(self):
        self.entries: List[Dict] = []
        self.partition_data = bytearray(b'\xff' * PARTITION_SIZE)
        self.current_offset = 0

    def add_certificate(self, tlv_type: tlv_type_t, cert_path: Union[str, bytes], subtype: int = 0) -> None:
        """Add certificate to partition"""
        cert_data = load_certificate(cert_path)

        # Add null terminator for PEM certificates
        if cert_data["encoding"] == serialization.Encoding.PEM.value:
            cert_path = cert_data["bytes"] + b'\0'
        else:
            cert_path = cert_data["bytes"]
        self.add_tlv_entry(tlv_type, subtype, cert_path, 0)

    def add_private_key(self, key_path: str, key_pass: Any = None,
                       key_type: tlv_priv_key_type_t = tlv_priv_key_type_t.ESP_SECURE_CERT_DEFAULT_FORMAT_KEY,
                       subtype: int = 0) -> None:
        """Add private key to partition"""
        if key_path and os.path.exists(key_path):
            key_data = load_private_key(key_path, key_pass)

            if key_data["encoding"] == serialization.Encoding.PEM.value:
                key_bytes = key_data["bytes"] + b'\0'
            else:
                key_bytes = key_data["bytes"]
        else:
            key_bytes = b''  # Empty for peripheral keys

        flags = _get_flag_byte(key_type)
        self.add_tlv_entry(tlv_type_t.ESP_SECURE_CERT_PRIV_KEY_TLV, subtype, key_bytes, flags)

    def add_ds_data(self, ciphertext: bytes, iv: bytes, rsa_key_len: int, subtype: int = 0) -> None:
        """Add DS data for RSA hardware acceleration"""
        # Create DS data structure: [key_len_param][iv][ciphertext]
        key_len_param = Int32sl.build(rsa_key_len // 32 - 1)  # Signed little-endian
        ds_data = key_len_param + iv + ciphertext

        self.add_tlv_entry(tlv_type_t.ESP_SECURE_CERT_DS_DATA_TLV, subtype, ds_data, 0)

    def add_ds_context(self, efuse_key_id: int, rsa_key_len: int, subtype: int = 0) -> None:
        """Add DS context for hardware acceleration"""
        # DS context structure must match exactly what the legacy code generated
        # From legacy code in tlv_format.py:
        # ds_context = struct.pack('<I', 0)                          # reserved:4 (32-bit little-endian)
        # ds_context = ds_context + struct.pack('<B', efuse_key_id)   # efuse_id:1 (8-bit)
        # ds_context = ds_context + struct.pack('<B', 0)             # padding:1 (8-bit)
        # ds_context = ds_context + struct.pack('<H', rsa_key_len)   # key_len:2 (16-bit little-endian)
        ds_context = Struct(
            "reserved" / Int32ul,      # 4 bytes reserved (32-bit unsigned little-endian)
            "efuse_key_id" / Int8ul,   # 1 byte efuse key ID (8-bit unsigned)
            "padding" / Int8ul,        # 1 byte padding (8-bit unsigned)
            "rsa_key_len" / Int16ul,   # 2 bytes RSA key length (16-bit unsigned little-endian)
        ).build({
            "reserved": 0,
            "efuse_key_id": efuse_key_id,
            "padding": 0,
            "rsa_key_len": rsa_key_len,
        })

        self.add_tlv_entry(tlv_type_t.ESP_SECURE_CERT_DS_CONTEXT_TLV, subtype, ds_context, 0)

    def add_security_config(self, efuse_key_id: int, subtype: int = 0) -> None:
        """Add security configuration"""
        # Security config: [priv_key_efuse_id:1][reserved:39]
        efuse_block_id = efuse_key_id + 4  # Convert to block ID
        sec_cfg = bytes([efuse_block_id]) + b'\x00' * 39

        self.add_tlv_entry(tlv_type_t.ESP_SECURE_CERT_SEC_CFG_TLV, subtype, sec_cfg, 0)

    def add_tlv_entry(self, tlv_type: Union[int, tlv_type_t], subtype: int,
                      data: bytes, flags: int) -> None:
        """Internal method to add TLV entry to partition"""
        if isinstance(tlv_type, tlv_type_t):
            tlv_type = tlv_type.value

        # Build TLV entry using construct
        tlv_data = {
            "header": {
                "magic": TLV_MAGIC,
                "flags": flags,
                "reserved": b'\x00\x00\x00',
                "type": tlv_type,
                "subtype": subtype,
                "length": len(data),
            },
            "data": data,
            "footer": {
                "crc": 0,  # Will be calculated below
            }
        }

        # Build the TLV without footer first to calculate CRC
        # TlvHeader.build() serializes this to binary
        header_and_data = TlvHeader.build(tlv_data["header"]) + data
        padding_len = _calculate_padding(len(data))
        padding = b'\x00' * padding_len
        crc_data = header_and_data + padding

        # Calculate CRC32
        crc = zlib.crc32(crc_data, 0xffffffff) & 0xffffffff
        tlv_data["footer"]["crc"] = crc

        # Build complete TLV entry
        complete_tlv = crc_data + TlvFooter.build(tlv_data["footer"])

        # Add to partition
        if self.current_offset + len(complete_tlv) > PARTITION_SIZE:
            raise ValueError(f"Partition size exceeded: {self.current_offset + len(complete_tlv)} > {PARTITION_SIZE}")

        self.partition_data[self.current_offset:self.current_offset + len(complete_tlv)] = complete_tlv
        self.current_offset += len(complete_tlv)

        self.entries.append({
            "type": tlv_type,
            "subtype": subtype,
            "length": len(data),
            "flags": flags,
            "offset": self.current_offset - len(complete_tlv)
        })

        print(f"Added TLV entry: type={tlv_type}, subtype={subtype}, length={len(complete_tlv)}")

    def build_partition(self, output_file: str) -> None:
        """Write partition to file with proper TLV termination"""
        # Add TLV termination marker at the end
        # This prevents the parser from reading uninitialized flash (0xFFFFFFFF)
        end_marker = struct.pack('<I', 0xFFFF)  # 16-bit end marker as used in the parser

        # Ensure we don't exceed partition size
        if self.current_offset + len(end_marker) > PARTITION_SIZE:
            raise ValueError(f"Cannot add end marker: partition size would exceed {PARTITION_SIZE} bytes")

        # Add the end marker
        self.partition_data[self.current_offset:self.current_offset + len(end_marker)] = end_marker
        self.current_offset += len(end_marker)

        with open(output_file, 'wb') as f:
            f.write(self.partition_data)

        print(f"Total TLV entries: {len(self.entries)}")
        print(f"Total partition size used: {self.current_offset} / {PARTITION_SIZE} bytes")
        print(f"Added TLV termination marker at offset: 0x{self.current_offset - len(end_marker):04X}")


class EspSecureCert:

    def __init__(self):
        # Initialize the list to store TLV entries
        self.secure_cert_entries = []
        # Create the directory esp_secure_cert_data if it does not exist
        if not os.path.exists(esp_secure_cert_data_dir):
            os.makedirs(esp_secure_cert_data_dir)

    def __del__(self):
        """Destructor - cleanup when object is destroyed"""
        self.esp_secure_cert_cleanup()

    def _is_private_key_entry(self, tlv_type: Union[int, tlv_type_t]) -> bool:
        """Check if entry is a private key"""
        return tlv_type == tlv_type_t.ESP_SECURE_CERT_PRIV_KEY_TLV.value

    def _is_certificate_entry(self, tlv_type: Union[int, tlv_type_t]) -> bool:
        """Check if entry is a certificate"""
        return tlv_type in [tlv_type_t.ESP_SECURE_CERT_CA_CERT_TLV.value, tlv_type_t.ESP_SECURE_CERT_DEV_CERT_TLV.value]

    def _validate_entry(self, entry: dict) -> bool:
        """Validate entry"""

        if entry.get('tlv_type') is None:
            raise ValueError("ERROR: Missing required 'tlv_type' in CSV")
        if entry.get('tlv_subtype') is None:
            raise ValueError("ERROR: Missing required 'tlv_subtype' in CSV")
        if not entry.get('data_value'):
            raise ValueError("ERROR: Missing required 'data_value' in CSV")
        if not entry.get('data_type'):
            raise ValueError("ERROR: Missing required 'data_type' in CSV")

        if not self._check_for_duplicate_tlv_entries(entry):
            raise ValueError("ERROR: Validation failed for duplicate entries")

        if self._is_private_key_entry(entry.get('tlv_type')):
            self._private_key_validation(entry)

        if (self._is_certificate_entry(entry.get('tlv_type')) or self._is_private_key_entry(entry.get('tlv_type'))) and entry.get('data_type') != 'file':
            entry['data_value'] = self._parse_data_from_any_format(entry['data_value'], entry['data_type'], True)
            entry['data_type'] = 'file'

        return True

    def _private_key_validation(self, entry: dict) -> bool:
        """Validate private key"""
        if entry.get('ds_enabled'):
            if entry.get('efuse_id') is None:
                raise ValueError("ERROR: Missing required 'efuse_id' in CSV")
        if entry.get('algorithm') is None:
            raise ValueError("ERROR: Missing required 'algorithm' in CSV")
        if entry.get('key_size') is None:
            raise ValueError("ERROR: Missing required 'key_size' in CSV")
        return True

    def _parse_data_from_any_format(self, data_value, data_type, output_file=False):
        """
        Process data content based on type:
        - 'file': return file path
        - 'content': write content to temp file and return path
        - 'string': return data as bytes (or temp file for certs/keys)
        - 'hex': return hex decoded bytes (or temp file for certs/keys)
        - 'base64': return base64 decoded bytes (or temp file for certs/keys)
        Returns: (processed_data, is_file_path)
        """
        # Check if this is a certificate or private key that needs file-based processing
        output_data = None

        if data_type == 'file':
            if not os.path.exists(data_value):
                raise FileNotFoundError(f"File not found: {data_value}")
            return data_value

        elif data_type == 'string':
            output_data = data_value.encode('utf-8')

        elif data_type == 'hex':
            output_data = bytes.fromhex(data_value.replace(' ', ''))

        elif data_type == 'base64':
            output_data = base64.b64decode(data_value)

        else:
            raise ValueError(f"Unsupported data_type: {data_type}")

        if output_file:
            temp_file = os.path.join(esp_secure_cert_data_dir, f'temp_key_{hash(str(data_value)) % 10000}.key')
            with open(temp_file, 'wb') as f:
                f.write(output_data)
            return temp_file
        return output_data

    def _check_for_duplicate_tlv_entries(self, entry):
        """Check for duplicate TLV entries (by tlv_type and tlv_subtype)"""

        # Check for duplicate subtypes within the same type
        # Check if the entry (by tlv_type and tlv_subtype) is already present in entries
        for existing_entry in self.secure_cert_entries:
            if (existing_entry.get('tlv_type') == entry.get('tlv_type') and
                existing_entry.get('tlv_subtype') == entry.get('tlv_subtype')):
                print(f"WARNING: Duplicate entry found for type {entry.get('tlv_type')}, subtype {entry.get('tlv_subtype')}")
                print(f"  - Existing entry: {existing_entry}")
                print(f"  - New entry: {entry}")
                return False
        return True

    def _strip_csv_row(self, row: dict) -> dict:
        """Optimized version using dictionary comprehension"""
        return {key: value.strip() if isinstance(value, str) else value
                for key, value in row.items()}


    def parse_esp_secure_cert_csv(self, csv_file):
        """Parse ESP Secure Cert CSV configuration file"""

        if not os.path.exists(csv_file):
            raise FileNotFoundError(f"CSV file not found: {csv_file}")

        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)

            for line_num, row in enumerate(reader, 1):
                # Strip all values once at the beginning (optimized)
                row = self._strip_csv_row(row)

                # Skip empty lines and comments
                if not row or (row.get('tlv_type', '').startswith('#')):
                    continue

                try:

                    if hasattr(tlv_format.tlv_type_t, row['tlv_type']):
                        tlv_type = getattr(tlv_format.tlv_type_t, row['tlv_type'])
                    else:
                        tlv_type = int(row['tlv_type'])

                    entry = {
                        'tlv_type': tlv_type,
                        'tlv_subtype': int(row['tlv_subtype']),
                        'data_value': row['data_value'],
                        'data_type': row['data_type'],
                        'priv_key_type': row['priv_key_type'].lower(),
                        'algorithm': row['algorithm'].upper(),
                        'key_size': int(row['key_size']) if row['key_size'] else 0,
                        'efuse_id': int(row['efuse_id']) if row['efuse_id'] else None,
                        'efuse_key_file': row['efuse_key'] if row['efuse_key'] else None,
                        'ds_enabled': row['priv_key_type'].lower() in ['rsa_ds', 'ecdsa_peripheral'],
                    }

                    self.add_entry(entry)

                except Exception as e:
                    print(f"Error parsing line {line_num}: {row}, error: {e}")
                    continue
        return

    def add_entry(self, entry):
        """
        Add an entry to entries after checking for duplicate (type, subtype).
        Returns True if added, False if duplicate found.
        """

        if entry['tlv_type'] == tlv_format.tlv_type_t.ESP_SECURE_CERT_PRIV_KEY_TLV:
            # Determine if DS (Digital Signature) is enabled for this private key
            entry['ds_enabled'] = entry['priv_key_type'] in ('rsa_ds', 'ecdsa_peripheral')
            entry['efuse_key_file'] = entry.get('efuse_key_file', '')
            entry['key_size'] = entry.get('key_size', 0)
            entry['algorithm'] = entry.get('algorithm', '')
            entry['private_key_pass'] = None

        # Add the processed entry to the list
        self._validate_entry(entry)
        self.secure_cert_entries.append(entry)

    def generate_esp_secure_cert(self, target_chip, port=None):
        """
        Process ESP Secure Cert CSV and generate partition.

        Args:
            target_chip (str): Target ESP chip (e.g., esp32c3, esp32s3)
            port (str, optional): Serial port for device communication.
                                If None, DS configuration will be done locally without device interaction.
        """

        try:
            # Group entries by type for better logging
            entries_by_type = {}
            for entry in self.secure_cert_entries:
                key_type = entry.get('tlv_type')
                if key_type not in entries_by_type:
                    entries_by_type[key_type] = []
                entries_by_type[key_type].append(entry)

            print("\n=== Entry Summary by Type ===")
            for tlv_type, type_entries in entries_by_type.items():
                print(f"Type {tlv_type}: {len(type_entries)} entries")
                for entry in type_entries:
                    print(f"  - Subtype {entry['tlv_subtype']}: {entry['data_type']} format")

            # Initialize DS variables for each configuration
            ds_tlv_entries = []  # Store results for each DS config

            # Handle DS configuration if enabled (only for private key entries)
            ds_enabled_entries = [entry for entry in self.secure_cert_entries if entry.get('ds_enabled', False)]
            if ds_enabled_entries:
                # Display operation mode information
                if port:
                    print(f"\n=== DS Configuration Mode: Device Connected (Port: {port}) ===")
                    print("INFO: DS keys will be burned to device eFuse blocks")
                else:
                    print("\n=== DS Configuration Mode: Local Only (No Port) ===")
                    print("WARNING: DS keys will be generated locally but NOT burned to device")
                    print("WARNING: You will need to manually burn the keys to device eFuse later")

                for entry in ds_enabled_entries:
                    ds_tlv_entry = {
                        'subtype': entry['tlv_subtype'],
                        'algorithm': entry['algorithm'],
                        'key_size': entry['key_size'],
                        'efuse_id': entry['efuse_id'],
                        'c': None,
                        'iv': None,
                        'rsa_key_len': entry['key_size']
                    }

                    if entry['algorithm'] == 'RSA':
                        efuse_key_file = get_efuse_key_file(entry['efuse_key_file'])
                        print(f"\nProcessing RSA DS configuration (subtype {entry['tlv_subtype']}):")
                        print(f"  - Key size: {entry['key_size']} bits")
                        print(f"  - eFuse key ID: {entry['efuse_id']}")
                        if efuse_key_file:
                            print(f"  - Using provided eFuse key file: {efuse_key_file}")
                        else:
                            print(f"  - Will generate new HMAC key file: {hmac_key_file}")

                        hmac_key = configure_ds.configure_efuse_for_rsa(
                            target_chip, port, hmac_key_file, efuse_key_file,
                            str(entry['key_size']), entry['data_value'],
                            None, entry['efuse_id']
                        )
                        c, iv, rsa_key_len = configure_ds.calculate_rsa_ds_params(
                            entry['data_value'], None, hmac_key, target_chip
                        )
                        ds_tlv_entry['c'] = c
                        ds_tlv_entry['iv'] = iv
                        ds_tlv_entry['rsa_key_len'] = rsa_key_len
                        print(f"  - RSA DS parameters calculated successfully")

                    elif entry['algorithm'] == 'ECDSA':
                        configure_ds.configure_efuse_for_ecdsa(
                            target_chip, port, ecdsa_key_file,
                            esp_secure_cert_data_dir, str(entry['key_size']),
                            entry['data_value'], None, entry['efuse_id']
                        )
                        print(f"  - ECDSA DS configuration completed successfully")

                    ds_tlv_entries.append(ds_tlv_entry)

            # Build TLV partition
            builder = TlvPartitionBuilder()

            # Auto-add DS-related TLVs for each DS configuration
            for ds_tlv_entry in ds_tlv_entries:
                if ds_tlv_entry['algorithm'] == 'RSA':
                    builder.add_ds_data(ds_tlv_entry['c'], ds_tlv_entry['iv'], ds_tlv_entry['rsa_key_len'], ds_tlv_entry['subtype'])
                    builder.add_ds_context(ds_tlv_entry['efuse_id'], ds_tlv_entry['rsa_key_len'], ds_tlv_entry['subtype'])
                elif ds_tlv_entry['algorithm'] == 'ECDSA':
                    builder.add_security_config(ds_tlv_entry['efuse_id'], ds_tlv_entry['subtype'])

            if not ds_tlv_entries:
                print("No DS configuration found")

            print("\n=== Processing TLV Entries ===")
            processed_count = 0
            for entry in self.secure_cert_entries:
                tlv_type = entry.get('tlv_type')
                tlv_subtype = entry.get('tlv_subtype')
                data_value = entry.get('data_value')
                data_type = entry.get('data_type')
                priv_key_type = entry['priv_key_type'] if 'priv_key_type' in entry else None
                configure_ds_enabled = entry['ds_enabled'] if 'ds_enabled' in entry else None

                print(f"Processing: Type {tlv_type}, Subtype {tlv_subtype}, Data Type: {data_type}")

                # Process data based on type
                try:
                    processed_data = self._parse_data_from_any_format(data_value, data_type, False)

                    # Handle certificates
                    if self._is_certificate_entry(tlv_type):  # CA_CERT or DEV_CERT
                        cert_type_name = "CA Certificate" if tlv_type == tlv_format.tlv_type_t.ESP_SECURE_CERT_CA_CERT_TLV else "Device Certificate"
                        print(f"  Adding {cert_type_name} (subtype {tlv_subtype})")
                        builder.add_certificate(tlv_type_t(tlv_type), processed_data, tlv_subtype)
                        processed_count += 1
                    # Handle private key
                    elif self._is_private_key_entry(tlv_type):  # PRIV_KEY
                        if priv_key_type == 'plaintext':
                            print(f"  Adding private key as plaintext for subtype {tlv_subtype}")
                            builder.add_private_key(processed_data, None, tlv_format.tlv_priv_key_type_t.ESP_SECURE_CERT_DEFAULT_FORMAT_KEY, tlv_subtype)
                            processed_count += 1
                        elif priv_key_type == 'rsa_ds' and configure_ds_enabled:
                            print(f"  Skipping private key TLV for subtype {tlv_subtype} (using hardware RSA DS)")
                            processed_count += 1
                            pass  # RSA DS private key is handled by DS data and context
                        elif priv_key_type == 'ecdsa_peripheral' and configure_ds_enabled:
                            print(f"  Adding private key for hardware ECDSA DS for subtype {tlv_subtype}")
                            builder.add_private_key(processed_data, None, tlv_format.tlv_priv_key_type_t.ESP_SECURE_CERT_ECDSA_PERIPHERAL_KEY, tlv_subtype)
                            processed_count += 1
                    else:  # Direct data processing
                        if data_type == 'file':
                            with open(processed_data, 'rb') as f:
                                processed_data = f.read()

                        else:
                            # If processed_data is a .bin file path, read its contents as bytes
                            if isinstance(processed_data, str) and processed_data.lower().endswith('.bin') and os.path.isfile(processed_data):
                                with open(processed_data, 'rb') as bin_f:
                                    bin_data = bin_f.read()
                                builder.add_tlv_entry(tlv_type, tlv_subtype, bin_data, 0)
                                print(f"  Added binary data from {processed_data} (subtype {tlv_subtype})")
                            else:
                                builder.add_tlv_entry(tlv_type, tlv_subtype, processed_data, 0)
                                print(f"  Skipping unknown TLV type {tlv_type} (subtype {tlv_subtype})")
                            processed_count += 1

                except Exception as e:
                    print(f"Error processing entry {tlv_type}: {e}")
                    continue

            print(f"\nSuccessfully processed {processed_count} out of {len(self.secure_cert_entries)} entries")

            # Build partition
            builder.build_partition(bin_filename)
            print(f'\nPartition generated: {bin_filename}')

            # Display summary
            print(f"\n=== ESP Secure Cert Generation Summary ===")
            print(f"Target chip: {target_chip}")
            print(f"Operation mode: {'Device Connected' if port else 'Local Only'}")
            print(f"Partition file: {bin_filename}")
            print(f"Total TLV entries: {len(self.secure_cert_entries)}")

            if ds_enabled_entries:
                print(f"DS peripheral entries: {len(ds_enabled_entries)}")
                if not port:
                    print("IMPORTANT: DS keys were generated locally. You must burn them to device eFuse manually:")
                    for entry in ds_enabled_entries:
                        efuse_key_file = get_efuse_key_file(entry['efuse_key_file'])
                        key_file = efuse_key_file if efuse_key_file else (ecdsa_key_file if entry['algorithm'] == 'ECDSA' else hmac_key_file)
                        if entry['algorithm'] == 'RSA':
                            print(f"  espefuse.py --chip {target_chip} -p <PORT> burn_key BLOCK_KEY{entry['efuse_id']} {key_file} HMAC_DOWN_DIGITAL_SIGNATURE")
                        elif entry['algorithm'] == 'ECDSA':
                            print(f"  espefuse.py --chip {target_chip} -p <PORT> burn_key BLOCK_KEY{entry['efuse_id']} <ecdsa_key.pem> ECDSA_KEY")

            print("=" * 50)

            return bin_filename

        except Exception as e:
            print(f'ERROR: Failed to process ESP Secure Cert CSV: {e}')
            import traceback
            traceback.print_exc()
            sys.exit(-1)


    # Flash esp_secure_cert partition after its generation
    # @info
    # The partition shall be flashed at the offset provided
    # for the --sec_cert_part_offset option.
    # The port is required for flashing the esp_secure_cert partition.
    # The flash_filename is the filename of the esp_secure_cert partition.
    def flash_esp_secure_cert_partition(self, idf_target, port, sec_cert_part_offset, flash_filename):
        """
        Flash the esp_secure_cert partition to the device.

        Args:
            idf_target (str): Target ESP chip
            port (str): Serial port for device communication
            sec_cert_part_offset (str): Flash offset for the partition
            flash_filename (str): Path to the partition binary file
        """
        print(f'\n=== Flashing ESP Secure Cert Partition ===')
        print(f'Partition file: {flash_filename}')
        print(f'Flash offset: {sec_cert_part_offset}')
        print('Note: You can skip this step by providing --skip_flash argument')

        # Check if the flash_filename exists
        if not os.path.exists(flash_filename):
            print(f"ERROR: The provided flash_filename {flash_filename} does not exist")
            sys.exit(-1)

        # Check if the port is provided
        if not port:
            print("WARNING: Port is not provided, skipping flash operation")
            print("INFO: Partition has been generated successfully but not flashed to device")
            print(f"To flash manually: esptool.py --chip {idf_target} -p <PORT> write_flash {sec_cert_part_offset} {flash_filename}")
            return

        flash_command = f"esptool.py --chip {idf_target} " + \
            f"-p {port} write_flash " + \
            f" {sec_cert_part_offset} {flash_filename}"
        try:
            flash_command_output = subprocess.check_output(
                flash_command,
                shell=True
            )
            print(flash_command_output.decode('utf-8'))
        except subprocess.CalledProcessError as e:
            print(e.output.decode("utf-8"))
            print('ERROR: Failed to execute the flash command')
            sys.exit(-1)

    def esp_secure_cert_cleanup(self):
        # Remove the directory esp_secure_cert_data
        if os.path.exists(esp_secure_cert_data_dir):
            for filename in os.listdir(esp_secure_cert_data_dir):
                if filename.startswith("temp_"):
                    file_path = os.path.join(esp_secure_cert_data_dir, filename)
                    if os.path.isfile(file_path):
                        os.remove(file_path)

    @staticmethod
    def parse_esp_secure_cert_bin(bin_file_path):
        """
        Parse an esp_secure_cert.bin file and generate CSV from parsed data.
        - CA/Device cert: extract, save as file, add row to CSV
        - Custom data: add row to CSV, no file
        - Private key:
          - plaintext: extract, save as file, add row to CSV
          - rsa_ds: add DS_DATA and DS_CONTEXT rows/files instead of priv key
          - ecdsa_peripheral: add SEC_CFG row/file instead of priv key
        All files are created in esp_secure_cert_parsed_data and referenced in the CSV.
        Adds efuse_id, key_size, algorithm, priv_key_type if possible.
        """
        output_dir = 'esp_secure_cert_parsed_data'
        content_dir = os.path.join(output_dir, "contents")
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        os.makedirs(output_dir)
        os.makedirs(content_dir)
        # Check if the file exists and is a .bin file
        if not os.path.isfile(bin_file_path):
            print(f"ERROR: The provided file '{bin_file_path}' does not exist or is not a file.")
            sys.exit(-1)
        if not bin_file_path.lower().endswith('.bin'):
            print(f"ERROR: The provided file '{bin_file_path}' is not a .bin file.")
            sys.exit(-1)
        # Check if the file is not empty and has a valid TLV header
        try:
            with open(bin_file_path, 'rb') as f:
                data = f.read()
            if len(data) == 0:
                print(f"ERROR: The provided .bin file '{bin_file_path}' is empty.")
                sys.exit(-1)
            # Check for valid TLV magic at the start
            if len(data) < 4:
                print(f"ERROR: The provided .bin file '{bin_file_path}' is too small to be a valid TLV partition.")
                sys.exit(-1)
            magic = int.from_bytes(data[0:4], 'little')

            if magic != TLV_MAGIC:
                print(f"ERROR: The provided .bin file '{bin_file_path}' does not have a valid TLV_MAGIC header (found 0x{magic:08X}).")
                sys.exit(-1)
        except Exception as e:
            print(f"ERROR: Failed to read or validate the .bin file '{bin_file_path}': {e}")
            sys.exit(-1)


        # Parse TLV entries
        tlv_entries = EspSecureCert._parse_tlv_entries_from_bin(bin_file_path)

        # Check if any TLV entries were actually parsed
        if not tlv_entries or len(tlv_entries) == 0:
            print(f"ERROR: No valid TLV entries found in the provided .bin file '{bin_file_path}'.")
            print("This file may not be a valid ESP Secure Cert partition or may be corrupted.")
            sys.exit(-1)

        # Group by type/subtype for lookup
        entries_by_type = {}
        for entry in tlv_entries:
            t = entry['header']['type']
            s = entry['header']['subtype']
            if t not in entries_by_type:
                entries_by_type[t] = {}
            entries_by_type[t][s] = entry
        # Prepare CSV rows
        csv_rows = []

        # Iterate and extract
        for entry in tlv_entries:
            t = entry['header']['type']
            s = entry['header']['subtype']
            data = entry['data']
            # CA cert
            if t == tlv_format.tlv_type_t.ESP_SECURE_CERT_CA_CERT_TLV:
                fname = f"cacert_{t}_{s}.pem"
                fpath = os.path.join(content_dir, fname)
                if data.startswith(b'-----BEGIN CERTIFICATE-----'):
                    with open(fpath, 'w') as f:
                        f.write(data.rstrip(b'\x00').decode('utf-8'))
                else:
                    fname = f"cacert_{t}_{s}.der"
                    fpath = os.path.join(content_dir, fname)
                    with open(fpath, 'wb') as f:
                        f.write(data)
                csv_rows.append({
                    'tlv_type': 'ESP_SECURE_CERT_CA_CERT_TLV',
                    'tlv_subtype': s,
                    'data_value': f"contents/{fname}",  # Reference file in contents subdirectory
                    'data_type': 'file',
                    'priv_key_type': '',
                    'algorithm': '',
                    'key_size': '',
                    'efuse_id': '',
                    'efuse_key': ''
                })
            # Device cert
            elif t == tlv_format.tlv_type_t.ESP_SECURE_CERT_DEV_CERT_TLV:
                fname = f"devcert_{t}_{s}.pem"
                fpath = os.path.join(content_dir, fname)
                if data.startswith(b'-----BEGIN CERTIFICATE-----'):
                    with open(fpath, 'w') as f:
                        f.write(data.rstrip(b'\x00').decode('utf-8'))
                else:
                    fname = f"devcert_{t}_{s}.der"
                    fpath = os.path.join(content_dir, fname)
                    with open(fpath, 'wb') as f:
                        f.write(data)
                csv_rows.append({
                    'tlv_type': 'ESP_SECURE_CERT_DEV_CERT_TLV',
                    'tlv_subtype': s,
                    'data_value': f"contents/{fname}",  # Reference file in contents subdirectory
                    'data_type': 'file',
                    'priv_key_type': '',
                    'algorithm': '',
                    'key_size': '',
                    'efuse_id': '',
                    'efuse_key': ''
                })
            # Private key
            elif t == tlv_format.tlv_type_t.ESP_SECURE_CERT_PRIV_KEY_TLV:
                # Plaintext
                fname = f"privkey_{t}_{s}.pem"
                fpath = os.path.join(content_dir, fname)
                algo = ''
                if data.startswith(b'-----BEGIN'):
                    key_bytes = data.rstrip(b'\x00')
                    pem_header = key_bytes.split(b'\n', 1)[0]
                    # Try to infer algorithm from PEM header
                    if b'RSA' in pem_header:
                        algo = 'RSA'
                    elif b'EC' in pem_header or b'ECDSA' in pem_header:
                        algo = 'ECDSA'
                    # PKCS#8: -----BEGIN PRIVATE KEY-----
                    if b'PRIVATE KEY-----' in pem_header and b'RSA' not in pem_header:
                        # Re-serialize as PKCS#8 using cryptography
                        from cryptography.hazmat.primitives import serialization
                        from cryptography.hazmat.backends import default_backend
                        key = serialization.load_pem_private_key(key_bytes, password=None, backend=default_backend())
                        pem = key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        )
                        with open(fpath, 'wb') as f:
                            f.write(pem)
                    else:
                        # PKCS#1 or other: write as-is
                        with open(fpath, 'w') as f:
                            f.write(key_bytes.decode('utf-8'))
                else:
                    fname = f"privkey_{t}_{s}.der"
                    fpath = os.path.join(content_dir, fname)
                    with open(fpath, 'wb') as f:
                        f.write(data)
                csv_rows.append({
                    'tlv_type': 'ESP_SECURE_CERT_PRIV_KEY_TLV',
                    'tlv_subtype': s,
                    'data_value': f"contents/{fname}",  # Reference file in contents subdirectory
                    'data_type': 'file',
                    'priv_key_type': 'plaintext',
                    'algorithm': algo,
                    'key_size': '',
                    'efuse_id': '',
                    'efuse_key': ''
                })
            # DS_DATA (if not already handled)
            elif t == tlv_format.tlv_type_t.ESP_SECURE_CERT_DS_DATA_TLV:
                if not any(r['tlv_type'] == 'ESP_SECURE_CERT_DS_DATA_TLV' and r['tlv_subtype'] == s for r in csv_rows):
                    fname = f"ds_data_{t}_{s}.bin"
                    fpath = os.path.join(content_dir, fname)
                    with open(fpath, 'wb') as f:
                        f.write(data)
                    key_size = ''
                    if len(data) >= 4:
                        key_size_val = struct.unpack('<i', data[:4])[0]
                        key_size = str((key_size_val + 1) * 32)
                    csv_rows.append({
                        'tlv_type': 'ESP_SECURE_CERT_DS_DATA_TLV',
                        'tlv_subtype': s,
                        'data_value': f"contents/{fname}",  # Reference file in contents subdirectory
                        'data_type': 'file',
                        'priv_key_type': 'rsa_ds',
                        'algorithm': 'RSA',
                        'key_size': key_size,
                        'efuse_id': '',
                        'efuse_key': ''
                    })
            # DS_CONTEXT (if not already handled)
            elif t == tlv_format.tlv_type_t.ESP_SECURE_CERT_DS_CONTEXT_TLV:
                if not any(r['tlv_type'] == 'ESP_SECURE_CERT_DS_CONTEXT_TLV' and r['tlv_subtype'] == s for r in csv_rows):
                    fname = f"ds_context_{t}_{s}.bin"
                    fpath = os.path.join(content_dir, fname)
                    with open(fpath, 'wb') as f:
                        f.write(data)
                    efuse_id = ''
                    ctx_key_size = ''
                    if len(data) >= 8:
                        efuse_id = str(data[4])
                        ctx_key_size = str(int.from_bytes(data[6:8], 'little'))
                    csv_rows.append({
                        'tlv_type': 'ESP_SECURE_CERT_DS_CONTEXT_TLV',
                        'tlv_subtype': s,
                        'data_value': f"contents/{fname}",  # Reference file in contents subdirectory
                        'data_type': 'file',
                        'priv_key_type': 'rsa_ds',
                        'algorithm': 'RSA',
                        'key_size': ctx_key_size,
                        'efuse_id': efuse_id,
                        'efuse_key': ''
                    })
            # # SEC_CFG (if not already handled)
            elif t == tlv_format.tlv_type_t.ESP_SECURE_CERT_SEC_CFG_TLV:
                if not any(r['tlv_type'] == 'ESP_SECURE_CERT_SEC_CFG_TLV' and r['tlv_subtype'] == s for r in csv_rows):
                    fname = f"sec_cfg_{t}_{s}.bin"
                    fpath = os.path.join(content_dir, fname)
                    with open(fpath, 'wb') as f:
                        f.write(data)
                    efuse_id = ''
                    if len(data) >= 1:
                        efuse_id = str(data[0] - 4)
                    csv_rows.append({
                        'tlv_type': 'ESP_SECURE_CERT_SEC_CFG_TLV',
                        'tlv_subtype': s,
                        'data_value': f"contents/{fname}",  # Reference file in contents subdirectory
                        'data_type': 'file',
                        'priv_key_type': 'ecdsa_peripheral',
                        'algorithm': 'ECDSA',
                        'key_size': '256',
                        'efuse_id': efuse_id,
                        'efuse_key': ''
                    })
            # Custom user data
            elif t >= tlv_format.tlv_type_t.ESP_SECURE_CERT_USER_DATA_1_TLV:
                try:
                    text = data.decode('utf-8')
                    if all(c.isprintable() or c.isspace() for c in text):
                        val = text
                        dtype = 'string'
                    else:
                        val = data.hex().upper()
                        dtype = 'hex'
                except Exception:
                    val = data.hex().upper()
                    dtype = 'hex'
                csv_rows.append({
                    'tlv_type': tlv_format.tlv_type_t(t).name,
                    'tlv_subtype': s,
                    'data_value': val,
                    'data_type': dtype,
                    'priv_key_type': '',
                    'algorithm': '',
                    'key_size': '',
                    'efuse_id': '',
                    'efuse_key': ''
                })

        # Check if any CSV rows were created (i.e., any valid entries were processed)
        if not csv_rows or len(csv_rows) == 0:
            print(f"ERROR: No valid TLV entries could be processed from the .bin file '{bin_file_path}'.")
            print("The file may contain only unknown or invalid TLV types.")
            sys.exit(-1)

        # Write CSV
        csv_file_path = os.path.join(output_dir, 'esp_secure_cert_parsed.csv')
        try:
            with open(csv_file_path, 'w', newline='') as csvfile:
                fieldnames = ['tlv_type', 'tlv_subtype', 'data_value', 'data_type', 'priv_key_type', 'algorithm', 'key_size', 'efuse_id', 'efuse_key']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(csv_rows)
        except Exception as e:
            print(f"ERROR: Could not write CSV file '{csv_file_path}': {e}")
            sys.exit(-1)

        # Write TLV partition full output to tlv_entries_raw.txt using tlv_parser.py's process_tlv_entries
        try:

            # Add the tools directory to sys.path if needed
            tools_dir = os.path.join(os.path.dirname(__file__), '..')
            tools_dir = os.path.abspath(tools_dir)
            if tools_dir not in sys.path:
                sys.path.insert(0, tools_dir)

            # Redirect stdout to capture all prints from process_tlv_entries
            summary_output = io.StringIO()
            sys_stdout = sys.stdout
            sys.stdout = summary_output
            tlv_parser.process_tlv_entries(bin_file_path)
            sys.stdout = sys_stdout
            summary_text = summary_output.getvalue()
            summary_output.close()
            # Normalize line endings and remove null bytes
            summary_text = summary_text.replace('\r\n', '\n').replace('\r', '\n').replace('\x00', '\n')
            with open(os.path.join(output_dir, 'tlv_entries_raw.txt'), 'w') as f:
                f.write(summary_text)
        except Exception as e:
            print(f"WARNING: Could not write tlv_entries_raw.txt: {e}")

        print(f"\nSuccessfully parsed binary file!")
        print(f"Generated files:")
        print(f"  - CSV file: {csv_file_path}")
        print(f"      - {len(csv_rows)} valid entries parsed")
        print(f"      - Entries:")
        for row in csv_rows:
            tlv_type = row.get('tlv_type', 'N/A')
            tlv_subtype = row.get('tlv_subtype', 'N/A')
            data_value = row.get('data_value', '')
            tlv_length = len(data_value) if data_value else 0
            if tlv_length > 0:
                print(f"        TLV type: {tlv_type}, subtype: {tlv_subtype}, length: {tlv_length}")
            else:
                print(f"        TLV type: {tlv_type}, subtype: {tlv_subtype}")
        print(f"  - tlv_entries_raw.txt: {os.path.join(output_dir, 'tlv_entries_raw.txt')}")
        print(f"  - All files in: {output_dir}")

    @staticmethod
    def _parse_tlv_entries_from_bin(bin_file_path):
        """
        Parse TLV entries from binary file using the same logic as tlv_parser.py
        Returns a list of dicts with header, data, and offset.
        """
        with open(bin_file_path, 'rb') as f:
            data = f.read()
        if len(data) == 0:
            raise ValueError("Binary file is empty")
        offset = 0
        tlv_entries = []
        while offset < len(data):
            try:
                tlv_header, header_size = tlv_parser.parse_tlv_header(data, offset)
                if tlv_header['magic'] == MAGIC_END:
                    break
                if tlv_header['magic'] != TLV_MAGIC:
                    break
                tlv_data_offset = offset + header_size
                padding_length = _calculate_padding(tlv_header['length'])
                tlv_data = data[tlv_data_offset:tlv_data_offset + tlv_header['length']]
                entry = {
                    'header': tlv_header,
                    'data': tlv_data,
                    'offset': offset
                }
                tlv_entries.append(entry)
                total_tlv_size = header_size + tlv_header['length'] + padding_length + 4  # +4 for CRC footer
                offset += total_tlv_size
            except Exception as e:
                print(f"Warning: Error parsing TLV at offset 0x{offset:04X}: {e}")
                break
        return tlv_entries
