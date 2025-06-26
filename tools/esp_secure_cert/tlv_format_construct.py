#!/usr/bin/env python3
"""
Enhanced TLV Format Generator using Construct Library
Provides improved readability, endianness handling, and custom TLV support
"""

import enum
import csv
import os
import sys
import zlib
import struct
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Tuple, Any, Optional
from construct import (Struct, Int32ul, Int8ul, Int16ul, Int32sl, Bytes, this)
from pathlib import Path

from esp_secure_cert.esp_secure_cert_helper import (
    load_private_key,
    load_certificate,
    _write_data_to_temp_file,
    get_efuse_key_file,
)
from cryptography.hazmat.primitives import serialization
from esp_secure_cert import configure_ds, tlv_format

# Sync with C enum esp_secure_cert_tlv_type_t
class TlvType(enum.IntEnum):
    CA_CERT = 0
    DEV_CERT = 1
    PRIV_KEY = 2
    DS_DATA = 3
    DS_CONTEXT = 4
    ECDSA_KEY_SALT = 5
    SEC_CFG = 6
    TLV_END = 50
    USER_DATA_1 = 51
    USER_DATA_2 = 52
    USER_DATA_3 = 53
    USER_DATA_4 = 54
    USER_DATA_5 = 55
    # Matter TLVs (reserved)
    MATTER_TLV_1 = 201
    MATTER_TLV_2 = 202
    # Limits
    TLV_MAX = 254
    TLV_INVALID = 255


class TlvSubtype(enum.IntEnum):
    SUBTYPE_0 = 0
    SUBTYPE_1 = 1
    SUBTYPE_2 = 2
    SUBTYPE_3 = 3
    SUBTYPE_4 = 4
    SUBTYPE_5 = 5
    SUBTYPE_MAX = 254
    SUBTYPE_INVALID = 255


class PrivKeyType(enum.IntEnum):
    INVALID_KEY = -1
    DEFAULT_FORMAT_KEY = 0
    HMAC_ENCRYPTED_KEY = 1
    HMAC_DERIVED_ECDSA_KEY = 2
    ECDSA_PERIPHERAL_KEY = 3
    RSA_DS_PERIPHERAL_KEY = 4


# Constants
MIN_ALIGNMENT_REQUIRED = 16
TLV_MAGIC = 0xBA5EBA11
PARTITION_SIZE = 0x2000  # 8KB

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


def _get_flag_byte(key_type: PrivKeyType) -> int:
    """Generate flag byte based on private key type"""
    flags = 0
    if key_type == PrivKeyType.HMAC_ENCRYPTED_KEY:
        flags |= (1 << 7)  # bit 7
    elif key_type == PrivKeyType.HMAC_DERIVED_ECDSA_KEY:
        flags |= (1 << 6)  # bit 6
    elif key_type == PrivKeyType.ECDSA_PERIPHERAL_KEY:
        flags |= (1 << 3)  # bit 3
    return flags

@dataclass
class CustomTlvEntry:
    """Represents a custom TLV entry from CSV data"""
    tlv_type: int
    subtype: int
    data: bytes
    flags: int

class TlvPartitionBuilder:
    """Builder class for creating TLV partitions with custom data support"""
    
    def __init__(self):
        self.entries: List[Dict] = []
        self.partition_data = bytearray(b'\xff' * PARTITION_SIZE)
        self.current_offset = 0
    
    def add_certificate(self, tlv_type: TlvType, cert_path: str, subtype: int = 0) -> None:
        """Add certificate to partition"""
        cert_data = load_certificate(cert_path)
        
        # Add null terminator for PEM certificates
        if cert_data["encoding"] == serialization.Encoding.PEM.value:
            cert_bytes = cert_data["bytes"] + b'\0'
        else:
            cert_bytes = cert_data["bytes"]
        
        self._add_tlv_entry(tlv_type, subtype, cert_bytes, 0)
    
    def add_private_key(self, key_path: str, key_pass: Any = None, 
                       key_type: PrivKeyType = PrivKeyType.DEFAULT_FORMAT_KEY,
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
        self._add_tlv_entry(TlvType.PRIV_KEY, subtype, key_bytes, flags)
    
    def add_ds_data(self, ciphertext: bytes, iv: bytes, rsa_key_len: int, subtype: int = 0) -> None:
        """Add DS data for RSA hardware acceleration"""
        # Create DS data structure: [key_len_param][iv][ciphertext]
        key_len_param = Int32sl.build(rsa_key_len // 32 - 1)  # Signed little-endian
        ds_data = key_len_param + iv + ciphertext
        
        self._add_tlv_entry(TlvType.DS_DATA, subtype, ds_data, 0)
    
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
        
        self._add_tlv_entry(TlvType.DS_CONTEXT, subtype, ds_context, 0)
    
    def add_security_config(self, efuse_key_id: int, subtype: int = 0) -> None:
        """Add security configuration"""
        # Security config: [priv_key_efuse_id:1][reserved:39]
        efuse_block_id = efuse_key_id + 4  # Convert to block ID
        sec_cfg = bytes([efuse_block_id]) + b'\x00' * 39
        
        self._add_tlv_entry(TlvType.SEC_CFG, subtype, sec_cfg, 0)
    
    def add_custom_entry(self, entry: CustomTlvEntry) -> None:
        """Add custom TLV entry"""
        self._add_tlv_entry(entry.tlv_type, entry.subtype, entry.data, entry.flags)
    
    def _add_tlv_entry(self, tlv_type: int | TlvType, subtype: int, 
                      data: bytes, flags: int) -> None:
        """Internal method to add TLV entry to partition"""
        if isinstance(tlv_type, TlvType):
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

    # Global variable to store all TLV entries from CSV as well as command line arguments
    secure_cert_entries = []

    @staticmethod
    def parse_esp_secure_cert_csv(csv_file):
        """Parse ESP Secure Cert CSV configuration file"""

        if not os.path.exists(csv_file):
            raise FileNotFoundError(f"CSV file not found: {csv_file}")

        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)

            for line_num, row in enumerate(reader, 1):
                # Skip empty lines and comments
                if not row or (row.get('tlv_type', '').strip().startswith('#')):
                    continue
                
                try:
                    tlv_type = row['tlv_type'].strip()
                    if 'tlv_subtype' not in row or not row['tlv_subtype'].strip():
                        raise ValueError(f"Missing required 'tlv_subtype' in CSV at line {line_num}: {row}")
                    tlv_subtype = int(row['tlv_subtype'])
                    data_value = row['data_value'].strip()
                    data_type = row['data_type'].strip()
                    priv_key_type = row['priv_key_type'].strip().lower()
                    algorithm = row['algorithm'].strip().upper()
                    key_size = int(row['key_size']) if row['key_size'] and row['key_size'].strip() else 0

                    # Get TLV type number using the enum directly
                    if hasattr(tlv_format.tlv_type_t, tlv_type):
                        tlv_type_num = getattr(tlv_format.tlv_type_t, tlv_type)
                    else:
                        tlv_type_num = int(tlv_type)

                    # Check if this is a private key entry that needs DS-related fields
                    is_private_key = tlv_type_num == tlv_format.tlv_type_t.ESP_SECURE_CERT_PRIV_KEY_TLV

                    # Automatically determine DS configuration from priv_key_type (only for private keys)
                    configure_ds_enabled = True if is_private_key and priv_key_type in ['rsa_ds', 'ecdsa_peripheral'] else False

                    efuse_id = None
                    if configure_ds_enabled:
                        if not row['efuse_id'] or not row['efuse_id'].strip():
                            raise ValueError(f"efuse_id is required but not provided in CSV at line {line_num}: {row}")
                        efuse_id = int(row['efuse_id'])

                    efuse_key = row['efuse_key'].strip() if row['efuse_key'] and row['efuse_key'].strip() else None

                    # Create base entry object with common fields
                    entry = {}

                    # Add DS-related fields only for private key entries
                    if is_private_key:
                        entry.update({
                            'tlv_type': tlv_type_num,
                            'tlv_subtype': tlv_subtype,
                            'data_value': data_value,
                            'data_type': data_type,
                            'ds_enabled': configure_ds_enabled,
                            'algorithm': algorithm if configure_ds_enabled else None,
                            'key_size': key_size if configure_ds_enabled else None,
                            'efuse_id': efuse_id,
                            'private_key_path': None,
                            'private_key_pass': None,
                            'efuse_key_file': efuse_key if configure_ds_enabled else None,
                            'priv_key_type': priv_key_type if configure_ds_enabled else 'plaintext',
                        })

                        # Set private key path for DS configuration if this is a private key entry
                        if configure_ds_enabled:
                            if data_type == 'file':
                                entry['private_key_path'] = data_value
                            else:
                                # For string private keys, write to temp file for DS operations
                                temp_file = _write_data_to_temp_file(data_value, 'string', tlv_type_num, text_mode=True, convert_newlines=True)
                                entry['private_key_path'] = temp_file
                    else:
                        entry.update({
                            'tlv_type': tlv_type_num,
                            'tlv_subtype': tlv_subtype,
                            'data_value': data_value,
                            'data_type': data_type,
                        })

                    if not EspSecureCert.check_for_duplicate_tlv_entries(entry):
                        print("ERROR: Validation failed for duplicate entries")
                        sys.exit(-1)

                    EspSecureCert.secure_cert_entries.append(entry)

                except Exception as e:
                    print(f"Error parsing line {line_num}: {row}, error: {e}")
                    continue  
        return
    
    @staticmethod
    def check_for_duplicate_tlv_entries(entry):
        """Check for duplicate TLV entries (by tlv_type and tlv_subtype)"""

        # Check for duplicate subtypes within the same type
        # Check if the entry (by tlv_type and tlv_subtype) is already present in entries
        for existing_entry in EspSecureCert.secure_cert_entries:
            if (existing_entry.get('tlv_type') == entry.get('tlv_type') and
                existing_entry.get('tlv_subtype') == entry.get('tlv_subtype')):
                print(f"WARNING: Duplicate entry found for type {entry.get('tlv_type')}, subtype {entry.get('tlv_subtype')}")
                print(f"  - Existing entry: {existing_entry}")
                print(f"  - New entry: {entry}")
                return False
        return True

    @staticmethod
    def process_data_content(data_value, data_type, tlv_type=None):
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
        is_cert_or_key = tlv_type in [
            tlv_format.tlv_type_t.ESP_SECURE_CERT_CA_CERT_TLV,
            tlv_format.tlv_type_t.ESP_SECURE_CERT_DEV_CERT_TLV,
            tlv_format.tlv_type_t.ESP_SECURE_CERT_PRIV_KEY_TLV
        ]

        if data_type == 'file':
            if not os.path.exists(data_value):
                raise FileNotFoundError(f"File not found: {data_value}")
            return data_value, True

        elif data_type == 'string':
            if is_cert_or_key:
                # For certificates and keys, write to temp file with proper newline handling
                temp_file = _write_data_to_temp_file(data_value, 'string', tlv_type, text_mode=True, convert_newlines=True)
                return temp_file, True
            else:
                return data_value.encode('utf-8'), False

        elif data_type == 'hex':
            data_bytes = bytes.fromhex(data_value.replace(' ', ''))
            if is_cert_or_key:
                # For certificates and keys, write to temp file for proper processing
                temp_file = _write_data_to_temp_file(data_bytes, 'hex', tlv_type, text_mode=False)
                return temp_file, True
            else:
                return data_bytes, False

        elif data_type == 'base64':
            import base64
            data_bytes = base64.b64decode(data_value)
            if is_cert_or_key:
                # For certificates and keys, write to temp file for proper processing
                temp_file = _write_data_to_temp_file(data_bytes, 'b64', tlv_type, text_mode=False)
                return temp_file, True
            else:
                return data_bytes, False

        else:
            raise ValueError(f"Unsupported data_type: {data_type}")
   
    @staticmethod
    def generate_esp_secure_cert(target_chip, port):
        """Process ESP Secure Cert CSV and generate partition"""

        try:
            # Group entries by type for better logging
            entries_by_type = {}
            for entry in EspSecureCert.secure_cert_entries:
                # For private key entries, use ds_tlv_type if present; otherwise, use tlv_type
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
            ds_enabled_entries = [entry for entry in EspSecureCert.secure_cert_entries if entry.get('ds_enabled', False)]
            if ds_enabled_entries:
                # Raise error if port is not provided. For other operations, port is not required.
                if not port:
                    raise ValueError("Port is required")

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
                        hmac_key = configure_ds.configure_efuse_for_rsa(
                            target_chip, port, hmac_key_file, efuse_key_file,
                            str(entry['key_size']), entry['private_key_path'],
                            None, entry['efuse_id']
                        )
                        c, iv, rsa_key_len = configure_ds.calculate_rsa_ds_params(
                            entry['private_key_path'], None, hmac_key, target_chip
                        )
                        ds_tlv_entry['c'] = c
                        ds_tlv_entry['iv'] = iv
                        ds_tlv_entry['rsa_key_len'] = rsa_key_len

                    elif entry['algorithm'] == 'ECDSA':
                        efuse_key_file = get_efuse_key_file(entry['efuse_key_file'])
                        configure_ds.configure_efuse_for_ecdsa(
                            target_chip, port, ecdsa_key_file, efuse_key_file,
                            esp_secure_cert_data_dir, str(entry['key_size']),
                            entry['private_key_path'], None, entry['efuse_id']
                        )

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
            for entry in EspSecureCert.secure_cert_entries:
                tlv_type = entry.get('tlv_type')
                tlv_subtype = entry.get('tlv_subtype')
                data_value = entry.get('data_value')
                data_type = entry.get('data_type')
                priv_key_type = entry['priv_key_type'] if 'priv_key_type' in entry else None
                configure_ds_enabled = entry['ds_enabled'] if 'ds_enabled' in entry else None

                print(f"Processing: Type {tlv_type}, Subtype {tlv_subtype}, Data Type: {data_type}")

                # Process data based on type
                try:
                    processed_data, is_file_path = EspSecureCert.process_data_content(data_value, data_type, tlv_type)

                    if is_file_path:  # File-based processing (files or content written to temp files)
                        # Handle certificates
                        if tlv_type in [tlv_format.tlv_type_t.ESP_SECURE_CERT_CA_CERT_TLV, tlv_format.tlv_type_t.ESP_SECURE_CERT_DEV_CERT_TLV]:  # CA_CERT or DEV_CERT
                            cert_type_name = "CA Certificate" if tlv_type == tlv_format.tlv_type_t.ESP_SECURE_CERT_CA_CERT_TLV else "Device Certificate"
                            print(f"  Adding {cert_type_name} (subtype {tlv_subtype})")
                            builder.add_certificate(TlvType(tlv_type), processed_data, tlv_subtype)
                            processed_count += 1

                        # Handle private key
                        elif tlv_type == tlv_format.tlv_type_t.ESP_SECURE_CERT_PRIV_KEY_TLV:  # PRIV_KEY
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

                        # Handle custom file data
                        elif tlv_type >= tlv_format.tlv_type_t.ESP_SECURE_CERT_USER_DATA_1_TLV:
                            with open(processed_data, 'rb') as f:
                                file_data = f.read()
                            print(f"  Adding user data (subtype {tlv_subtype}) from file")
                            builder._add_tlv_entry(tlv_type, tlv_subtype, file_data, 0)
                            processed_count += 1

                    else:  # Direct data processing
                        print(f"  Adding direct data (subtype {tlv_subtype})")
                        builder._add_tlv_entry(tlv_type, tlv_subtype, processed_data, 0)
                        processed_count += 1

                except Exception as e:
                    print(f"Error processing entry {tlv_type}: {e}")
                    continue
                
            print(f"\nSuccessfully processed {processed_count} out of {len(EspSecureCert.secure_cert_entries)} entries")

            # Build partition
            builder.build_partition(bin_filename)
            print(f'\nPartition generated: {bin_filename}')

            return bin_filename

        except Exception as e:
            print(f'ERROR: Failed to process ESP Secure Cert CSV: {e}')
            import traceback
            traceback.print_exc()
            sys.exit(-1)

    @staticmethod
    def add_entry(entry):
        """
        Add an entry to entries after checking for duplicate (type, subtype).
        Returns True if added, False if duplicate found.
        """
        if EspSecureCert.check_for_duplicate_tlv_entries(entry):

            if entry['tlv_type'] == tlv_format.tlv_type_t.ESP_SECURE_CERT_PRIV_KEY_TLV:
                if entry['priv_key_type'] == 'rsa_ds' or entry['priv_key_type'] == 'ecdsa_peripheral':
                    entry['ds_enabled'] = True
                else:
                    entry['ds_enabled'] = False

                entry['private_key_path'] = entry['data_value']
                entry['efuse_key_file'] = entry['efuse_key'] if entry['efuse_key'] else ''
                if entry['efuse_id'] is None and entry['ds_enabled']:
                    raise ValueError(f"efuse_id is required but not provided in tlv_type {entry['tlv_type']} and tlv_subtype {entry['tlv_subtype']}")
                entry['efuse_id'] = entry['efuse_id']
                entry['key_size'] = entry['key_size'] if entry['key_size'] else 0
                entry['algorithm'] = entry['algorithm'] if entry['algorithm'] else ''
                entry['private_key_pass'] = None
            
            EspSecureCert.secure_cert_entries.append(entry)
        
        else:
            print(f"ERROR: Duplicate entry found for type {entry.get('tlv_type')}, subtype {entry.get('tlv_subtype')}")
            sys.exit(-1)

    # Flash esp_secure_cert partition after its generation
    # @info
    # The partition shall be flashed at the offset provided
    # for the --sec_cert_part_offset option.
    # The port is required for flashing the esp_secure_cert partition.
    # The flash_filename is the filename of the esp_secure_cert partition.
    @staticmethod
    def flash_esp_secure_cert_partition(idf_target, port, sec_cert_part_offset, flash_filename):
        print(f'Flashing the esp_secure_cert partition at {sec_cert_part_offset} offset')
        print('Note: You can skip this step by providing --skip_flash argument')

        # Check if the flash_filename exists
        if not os.path.exists(flash_filename):
            print(f"ERROR: The provided flash_filename {flash_filename} does not exist")
            sys.exit(-1)

        # Check if the port is provided
        if not port:
            print("ERROR: Port is required for flashing the esp_secure_cert partition")
            sys.exit(-1)

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
