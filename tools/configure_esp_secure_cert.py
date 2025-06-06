#!/usr/bin/env python
# SPDX-FileCopyrightText: 2020-2022 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
import argparse
import os
import subprocess
import sys
import csv
from esp_secure_cert import nvs_format, custflash_format
from esp_secure_cert import configure_ds, tlv_format
from esp_secure_cert.tlv_format_construct import (
    TlvPartitionBuilder, 
    TlvType,
    PrivKeyType,
    read_partition_tlvs
)
from esp_secure_cert.efuse_helper import (
    log_efuse_summary,
    configure_efuse_key_block,
)
from esp_secure_cert.esp_secure_cert_helper import (
    _write_data_to_temp_file,
    get_efuse_key_file,
)

# Check python version is proper or not to avoid script failure
assert sys.version_info >= (3, 6, 0), 'Python version too low.'

esp_secure_cert_data_dir = 'esp_secure_cert_data'
# hmac_key_file is generated when HMAC_KEY is calculated,
# it is used when burning HMAC_KEY to efuse
hmac_key_file = os.path.join(esp_secure_cert_data_dir, 'hmac_key.bin')
ecdsa_key_file = os.path.join(esp_secure_cert_data_dir, 'ecdsa_key.bin')
# csv and bin filenames are default filenames
# for nvs partition files created with this script
csv_filename = os.path.join(esp_secure_cert_data_dir, 'esp_secure_cert.csv')
bin_filename = os.path.join(esp_secure_cert_data_dir, 'esp_secure_cert.bin')
# Targets supported by the script
supported_targets = {'esp32', 'esp32s2', 'esp32c3', 'esp32s3',
                     'esp32c6', 'esp32h2', 'esp32p4'}


# Flash esp_secure_cert partition after its generation
#
# @info
# The partition shall be flashed at the offset provided
# for the --sec_cert_part_offset option
def flash_esp_secure_cert_partition(idf_target,
                                    port, sec_cert_part_offset,
                                    flash_filename):
    print('Flashing the esp_secure_cert partition at {0} offset'
          .format(sec_cert_part_offset))
    print('Note: You can skip this step by providing --skip_flash argument')
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


def cleanup(args):
    if args.keep_ds_data is False:
        if os.path.exists(hmac_key_file):
            os.remove(hmac_key_file)
        if os.path.exists(csv_filename):
            os.remove(csv_filename)


def main():
    parser = argparse.ArgumentParser(description='''
    The python utility helps to configure and provision
    the device with PKI credentials, to generate the esp_secure_cert partition.
    The utility also configures the DS peripheral on the SoC if available.
    ''')

    parser.add_argument(
        '--private-key',
        dest='privkey',
        default='client.key',
        metavar='relative/path/to/client-priv-key',
        help='relative path to client private key')

    parser.add_argument(
        '--pwd', '--password',
        dest='priv_key_pass',
        metavar='[password]',
        help='the password associated with the private key')

    parser.add_argument(
        '--device-cert',
        dest='device_cert',
        default=None,
        metavar='relative/path/to/device-cert',
        help='relative path to device/client certificate '
             '(which contains the public part of the client private key) ')

    parser.add_argument(
        '--ca-cert',
        dest='ca_cert',
        default='ca.crt',
        metavar='relative/path/to/ca-cert',
        help='relative path to ca certificate which '
             'has been used to sign the client certificate')

    parser.add_argument(
        '--target_chip',
        dest='target_chip', type=str,
        choices=supported_targets,
        default='esp32c3',
        metavar='target chip',
        help='The target chip e.g. esp32s2, s3, c3')

    parser.add_argument(
        '--summary',
        dest='summary', action='store_true',
        help='Provide this option to print efuse summary of the chip')

    parser.add_argument(
        '--secure_cert_type',
        dest='sec_cert_type', type=str,
        choices={'cust_flash_tlv', 'cust_flash', 'nvs'},
        default='cust_flash_tlv',
        metavar='type of secure_cert partition',
        help='The type of esp_secure_cert partition. '
             'Can be \"cust_flash_tlv\" or \"cust_flash\" or \"nvs\". '
             'Please note that \"cust_flash\" and \"nvs\" are legacy formats.')

    parser.add_argument(
        '--configure_ds',
        dest='configure_ds', action='store_true',
        help='Provide this option to configure the DS peripheral.')

    parser.add_argument(
        '--skip_flash',
        dest='skip_flash', action='store_true',
        help='Provide this option to skip flashing the'
             ' esp_secure_cert partition at the value'
             ' provided to sec_cert_part_offset option')

    parser.add_argument(
        '--efuse_key_id',
        dest='efuse_key_id', type=int, choices=range(0, 6),
        metavar='[key_id] ',
        default=1,
        help='Provide the efuse key_id which '
             'contains/will contain HMAC_KEY, default is 1')

    parser.add_argument(
        '--efuse_key_file',
        help='eFuse key file which contains the '
             'key that shall be burned in '
             'the eFuse (e.g. HMAC key, ECDSA key)',
        metavar='[/path/to/efuse key file]')

    parser.add_argument(
        '--port', '-p',
        dest='port',
        metavar='[port]',
        required=False,
        help='UART com port to which the ESP device is connected')

    parser.add_argument(
        '--keep_ds_data_on_host', '-keep_ds_data',
        dest='keep_ds_data', action='store_true',
        help='Keep encrypted private key data and key '
             'on host machine for testing purpose')

    parser.add_argument(
        '--sec_cert_part_offset',
        dest='sec_cert_part_offset',
        default='0xD000',
        help='The flash offset of esp_secure_cert partition'
             ' Hex value must be given e.g. 0xD000')

    parser.add_argument(
        '--priv_key_algo',
        help='Signing algorithm used by the private key '
             ', e.g. RSA 2048, ECDSA 256',
        nargs=2, required=False,
        metavar='[sign algorithm, key size]')

    parser.add_argument(
        '--esp_secure_cert_csv',
        dest='esp_secure_cert_csv',
        metavar='[/path/to/esp_secure_cert_config.csv]',
        help='CSV file containing ESP Secure Cert contents (TLV entries, custom data). ')

    args = parser.parse_args()

    # Handle ESP Secure Cert CSV processing
    if args.esp_secure_cert_csv:
        process_esp_secure_cert_csv(args)
        return

    # Validate required arguments for traditional mode
    if not args.esp_secure_cert_csv:
        if not args.priv_key_algo:
            parser.error("--priv_key_algo is required when not using --esp_secure_cert_csv")
        if not args.port:
            parser.error("--port is required when not using --esp_secure_cert_csv")

    idf_target = args.target_chip
    if idf_target not in supported_targets:
        if idf_target is not None:
            print('ERROR: The script does not support '
                  'the target {}'.format(idf_target))
        sys.exit(-1)
    idf_target = str(idf_target)

    if args.summary is not False:
        log_efuse_summary(idf_target, args.port)
        sys.exit(0)

    if (os.path.exists(args.privkey) is False):
        print('ERROR: The provided private key file does not exist')
        sys.exit(-1)

    if (args.device_cert is not None):
        if (os.path.exists(args.device_cert) is False):
            print('ERROR: The provided client cert file does not exist')
            sys.exit(-1)

    if (os.path.exists(esp_secure_cert_data_dir) is False):
        os.makedirs(esp_secure_cert_data_dir)

    # Provide CA cert path only if it exists
    ca_cert = None
    if (os.path.exists(args.ca_cert) is True):
        ca_cert = os.path.abspath(args.ca_cert)

    c = None
    iv = None
    key_size = None

    if args.configure_ds is not False:
        if args.priv_key_algo[0] == 'RSA':
            efuse_key_file = args.efuse_key_file
            hmac_key =  configure_ds.configure_efuse_for_rsa(idf_target, args.port, hmac_key_file, efuse_key_file, args.priv_key_algo[1], args.privkey, args.priv_key_pass, args.efuse_key_id)
            # Calculate the encrypted private key data along
            # with all other parameters
            c, iv, key_size = configure_ds.calculate_rsa_ds_params(args.privkey,  # type: ignore # noqa: E501
                                                                   args.priv_key_pass,  # type: ignore # noqa: E501
                                                                   hmac_key,
                                                                   idf_target)
        elif args.priv_key_algo[0] == 'ECDSA':
            efuse_key_file = args.efuse_key_file
            configure_ds.configure_efuse_for_ecdsa(idf_target, args.port, ecdsa_key_file, efuse_key_file, esp_secure_cert_data_dir, args.priv_key_algo[1], args.privkey, args.priv_key_pass, args.efuse_key_id)
        else:
            raise ValueError('Invalid priv key algorithm '
                             f'{args.priv_key_algo[0]}')

    else:
        print('--configure_ds option not set. '
              'Configuring without use of DS peripheral.')
        print('WARNING: Not Secure.\n'
              'the private shall be stored as plaintext')

    if args.sec_cert_type == 'cust_flash_tlv':
        key_type = tlv_format.tlv_priv_key_type_t.ESP_SECURE_CERT_DEFAULT_FORMAT_KEY  # type: ignore # noqa: E501
        tlv_priv_key = tlv_format.tlv_priv_key_t(key_type,
                                                 args.privkey,
                                                 args.priv_key_pass)

        if args.configure_ds is not False:
            if args.priv_key_algo[0] == 'RSA':
                tlv_priv_key.key_type = tlv_format.tlv_priv_key_type_t.ESP_SECURE_CERT_RSA_DS_PERIPHERAL_KEY  # type: ignore # noqa: E501
                tlv_priv_key.ciphertext = c
                tlv_priv_key.iv = iv
                tlv_priv_key.efuse_key_id = args.efuse_key_id
                tlv_priv_key.priv_key_len = key_size

                tlv_format.generate_partition_ds(tlv_priv_key,
                                                 args.device_cert,
                                                 ca_cert, idf_target,
                                                 bin_filename)
            if args.priv_key_algo[0] == 'ECDSA':
                tlv_priv_key.key_type = tlv_format.tlv_priv_key_type_t.ESP_SECURE_CERT_ECDSA_PERIPHERAL_KEY  # type: ignore # noqa: E501
                print('Generating ECDSA partition')
                tlv_priv_key.efuse_key_id = args.efuse_key_id
                priv_key_len = int(args.priv_key_algo[1], 10)
                tlv_priv_key.priv_key_len = priv_key_len
                tlv_format.generate_partition_ds(tlv_priv_key,
                                                 args.device_cert,
                                                 ca_cert, idf_target,
                                                 bin_filename)
        else:
            tlv_format.generate_partition_no_ds(tlv_priv_key,
                                                args.device_cert,
                                                ca_cert, idf_target,
                                                bin_filename)
    elif args.sec_cert_type == 'cust_flash':
        if args.configure_ds is not False:
            custflash_format.generate_partition_ds(c, iv, args.efuse_key_id,
                                                   key_size, args.device_cert,
                                                   ca_cert, idf_target,
                                                   bin_filename)
        else:
            custflash_format.generate_partition_no_ds(args.device_cert,
                                                      ca_cert,
                                                      args.privkey,
                                                      args.priv_key_pass,
                                                      idf_target, bin_filename)
    elif args.sec_cert_type == 'nvs':
        # Generate csv file for the DS data and generate an NVS partition.
        if args.configure_ds is not False:
            nvs_format.generate_csv_file_ds(c, iv, args.efuse_key_id,
                                            key_size, args.device_cert,
                                            ca_cert, csv_filename)
        else:
            nvs_format.generate_csv_file_no_ds(args.device_cert, ca_cert,
                                               args.privkey,
                                               args.priv_key_pass,
                                               csv_filename)
        nvs_format.generate_partition(csv_filename, bin_filename)

    if args.skip_flash is False:
        flash_esp_secure_cert_partition(idf_target,
                                        args.port,
                                        args.sec_cert_part_offset,
                                        bin_filename)

    cleanup(args)


def parse_esp_secure_cert_csv(csv_file):
    """Parse ESP Secure Cert CSV configuration file"""
    
    if not os.path.exists(csv_file):
        raise FileNotFoundError(f"CSV file not found: {csv_file}")
    
    entries = []
    ds_configs = []  # List to store multiple DS configurations
    ds_config = {
        'enabled': False,
        'algorithm': None,
        'key_size': None,
        'efuse_id': None,
        'private_key_path': None,
        'private_key_pass': None,
        'efuse_key_file': None
    }
    
    with open(csv_file, 'r') as f:
        reader = csv.reader(f)
        
        for line_num, row in enumerate(reader, 1):
            # Skip empty lines and comments
            if not row or (row[0] and row[0].strip().startswith('#')):
                continue
            
            # Ensure we have enough columns (9 columns after removing password)
            while len(row) < 9:
                row.append('')
            
            try:
                tlv_type = row[0].strip()
                tlv_subtype = int(row[1]) if row[1].strip() else 0
                data_value = row[2].strip()
                data_type = row[3].strip().lower()
                priv_key_type = row[4].strip().lower()
                algorithm = row[5].strip().upper()
                key_size = int(row[6]) if row[6].strip() else 0
                # efuse_id is compulsory only for private key entries
                if tlv_type == 'ESP_SECURE_CERT_PRIV_KEY_TLV':
                    if not row[7].strip():
                        raise ValueError(f"efuse_id is required but not provided in CSV at line {line_num}: {row}")
                    efuse_id = int(row[7])
                else:
                    efuse_id = int(row[7]) if row[7].strip() else 0
                efuse_key = row[8].strip() if len(row) > 8 and row[8].strip() else None
                
                # Get TLV type number using the enum directly
                if hasattr(tlv_format.tlv_type_t, tlv_type):
                    tlv_type_num = getattr(tlv_format.tlv_type_t, tlv_type)
                else:
                    tlv_type_num = int(tlv_type)
                
                # Automatically determine DS configuration from priv_key_type
                configure_ds_enabled = True if priv_key_type in ['rsa_ds', 'ecdsa_peripheral'] else False
                if configure_ds_enabled:
                    # Create individual DS config for this private key
                    individual_ds_config = {
                        'enabled': True,
                        'algorithm': algorithm,
                        'key_size': key_size,
                        'efuse_id': efuse_id,
                        'private_key_path': None,
                        'private_key_pass': None,
                        'efuse_key_file': efuse_key,
                        'tlv_subtype': tlv_subtype,
                        'priv_key_type': priv_key_type
                    }
                    
                    if tlv_type_num == tlv_format.tlv_type_t.ESP_SECURE_CERT_PRIV_KEY_TLV:  # PRIV_KEY
                        if data_type == 'file':
                            individual_ds_config['private_key_path'] = data_value
                        else:
                            # For string private keys, write to temp file for DS operations
                            temp_file = _write_data_to_temp_file(data_value, 'string', tlv_type_num, text_mode=True, convert_newlines=True)
                            individual_ds_config['private_key_path'] = temp_file
                    
                    ds_configs.append(individual_ds_config)
                    
                    # Set the main DS config to enabled if any DS is configured
                    ds_config['enabled'] = True
                
                entry = {
                    'tlv_type': tlv_type_num,
                    'tlv_subtype': tlv_subtype,
                    'data_value': data_value,
                    'data_type': data_type,
                    'priv_key_type': priv_key_type,
                    'algorithm': algorithm,
                    'key_size': key_size,
                    'efuse_id': efuse_id,
                    'configure_ds': configure_ds_enabled,
                    'efuse_key': efuse_key
                }
                
                entries.append(entry)
                
            except Exception as e:
                print(f"Error parsing line {line_num}: {row}, error: {e}")
                continue
    
    return entries, ds_config, ds_configs


def validate_multiple_entries(entries):
    """Validate that multiple entries are properly configured"""
    
    # Check for duplicate subtypes within the same type
    entries_by_type = {}
    for entry in entries:
        tlv_type = entry['tlv_type']
        tlv_subtype = entry['tlv_subtype']
        
        if tlv_type not in entries_by_type:
            entries_by_type[tlv_type] = {}
        
        if tlv_subtype in entries_by_type[tlv_type]:
            print(f"WARNING: Duplicate subtype {tlv_subtype} found for type {tlv_type}")
            print(f"  - First entry: {entries_by_type[tlv_type][tlv_subtype]}")
            print(f"  - Second entry: {entry}")
            return False
        
        entries_by_type[tlv_type][tlv_subtype] = entry
    
    return True

def process_esp_secure_cert_csv(args):
    """Process ESP Secure Cert CSV and generate partition"""
    print(f'Loading ESP Secure Cert configuration from: {args.esp_secure_cert_csv}')
    
    try:
        if not args.port:
            raise ValueError("Port is required")

        entries, ds_config, ds_configs = parse_esp_secure_cert_csv(args.esp_secure_cert_csv)
        print(f'Loaded {len(entries)} TLV entries')
        print(f'DS Configuration: {ds_config}')
        print(f'Found {len(ds_configs)} DS configurations')
        
        # Validate multiple entries
        if not validate_multiple_entries(entries):
            print("ERROR: Validation failed for multiple entries")
            sys.exit(-1)
        
        # Group entries by type for better logging
        entries_by_type = {}
        for entry in entries:
            tlv_type = entry['tlv_type']
            if tlv_type not in entries_by_type:
                entries_by_type[tlv_type] = []
            entries_by_type[tlv_type].append(entry)
        
        print("\n=== Entry Summary by Type ===")
        for tlv_type, type_entries in entries_by_type.items():
            print(f"Type {tlv_type}: {len(type_entries)} entries")
            for entry in type_entries:
                print(f"  - Subtype {entry['tlv_subtype']}: {entry['data_type']} format")
        
        # Initialize DS variables for each configuration
        ds_results = []  # Store results for each DS config
        
        # Handle DS configuration if enabled
        if ds_config['enabled']:
            
            for i, individual_ds_config in enumerate(ds_configs):
                
                ds_result = {
                    'subtype': individual_ds_config['tlv_subtype'],
                    'algorithm': individual_ds_config['algorithm'],
                    'key_size': individual_ds_config['key_size'],
                    'efuse_id': individual_ds_config['efuse_id'],
                    'c': None,
                    'iv': None,
                    'rsa_key_len': individual_ds_config['key_size']
                }
                
                if individual_ds_config['algorithm'] == 'RSA':
                    efuse_key_file = get_efuse_key_file(individual_ds_config['efuse_key_file'])
                    hmac_key = configure_ds.configure_efuse_for_rsa(
                        args.target_chip, args.port, hmac_key_file, efuse_key_file,
                        str(individual_ds_config['key_size']), individual_ds_config['private_key_path'],
                        None, individual_ds_config['efuse_id']
                    )
                    c, iv, rsa_key_len = configure_ds.calculate_rsa_ds_params(
                        individual_ds_config['private_key_path'], None, hmac_key, args.target_chip
                    )
                    ds_result['c'] = c
                    ds_result['iv'] = iv
                    ds_result['rsa_key_len'] = rsa_key_len
                    
                elif individual_ds_config['algorithm'] == 'ECDSA':
                    efuse_key_file = get_efuse_key_file(individual_ds_config['efuse_key_file'])
                    configure_ds.configure_efuse_for_ecdsa(
                        args.target_chip, args.port, ecdsa_key_file, efuse_key_file,
                        esp_secure_cert_data_dir, str(individual_ds_config['key_size']),
                        individual_ds_config['private_key_path'], None, individual_ds_config['efuse_id']
                    )
                
                ds_results.append(ds_result)
        
        # Build TLV partition
        builder = TlvPartitionBuilder()
        
        # Auto-add DS-related TLVs for each DS configuration
        for ds_result in ds_results:
            if ds_result['algorithm'] == 'RSA':
                builder.add_ds_data(ds_result['c'], ds_result['iv'], ds_result['rsa_key_len'], ds_result['subtype'])
                builder.add_ds_context(ds_result['efuse_id'], ds_result['rsa_key_len'], ds_result['subtype'])
            elif ds_result['algorithm'] == 'ECDSA':
                builder.add_security_config(ds_result['efuse_id'], ds_result['subtype'])
        
        if not ds_results:
            print("No DS configuration found")

        print("\n=== Processing TLV Entries ===")
        processed_count = 0
        for entry in entries:
            tlv_type = entry['tlv_type']
            tlv_subtype = entry['tlv_subtype']
            data_value = entry['data_value']
            data_type = entry['data_type']
            priv_key_type = entry['priv_key_type']
            configure_ds_enabled = entry['configure_ds']
            
            print(f"Processing: Type {tlv_type}, Subtype {tlv_subtype}, Data Type: {data_type}")
            
            # Process data based on type
            try:
                processed_data, is_file_path = process_data_content(data_value, data_type, tlv_type)
                
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
        
        print(f"\nSuccessfully processed {processed_count} out of {len(entries)} entries")
        
        # Build partition
        builder.build_partition(bin_filename)
        print(f'\nPartition generated: {bin_filename}')
        
        # Flash partition
        if not args.skip_flash:
            flash_esp_secure_cert_partition(args.target_chip, args.port, '0xD000', bin_filename)
        else:
            print(f'To flash manually: esptool.py --chip {args.target_chip} -p {args.port} write_flash 0xD000 {bin_filename}')
            
    except Exception as e:
        print(f'ERROR: Failed to process ESP Secure Cert CSV: {e}')
        import traceback
        traceback.print_exc()
        sys.exit(-1)

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

if __name__ == '__main__':
    main()
