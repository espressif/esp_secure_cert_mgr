#!/usr/bin/env python
# SPDX-FileCopyrightText: 2020-2022 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
import argparse
import hashlib
import hmac
import json
import os
import struct
import subprocess
import sys
import zlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.utils import int_to_bytes


idf_path = os.getenv('IDF_PATH')

try:
    import nvs_partition_gen as nvs_gen
except ImportError:
    if not idf_path or not os.path.exists(idf_path):
        raise Exception('IDF_PATH not found')
    sys.path.insert(0, os.path.join(idf_path, 'components',
                    'nvs_flash', 'nvs_partition_generator'))
    import nvs_partition_gen as nvs_gen

# Check python version is proper or not to avoid script failure
assert sys.version_info >= (3, 6, 0), 'Python version too low.'

esp_ds_data_dir = 'esp_ds_data'
# hmac_key_file is generated when HMAC_KEY is calculated,
# it is used when burning HMAC_KEY to efuse
hmac_key_file = os.path.join(esp_ds_data_dir, 'hmac_key.bin')
# csv and bin filenames are default filenames
# for nvs partition files created with this script
csv_filename = os.path.join(esp_ds_data_dir, 'esp_secure_cert.csv')
bin_filename = os.path.join(esp_ds_data_dir, 'esp_secure_cert.bin')
# Targets supported by the script
supported_targets = {'esp32s2', 'esp32c3', 'esp32s3'}
supported_key_size = {'esp32s2': [1024, 2048, 3072, 4096],
                      'esp32c3': [1024, 2048, 3072],
                      'esp32s3': [1024, 2048, 3072, 4096]}


def load_privatekey(key_file_path, password=None):
    key_file = open(key_file_path, 'rb')
    key = key_file.read()
    key_file.close()
    return serialization.load_pem_private_key(key,
                                              password=password,
                                              backend=default_backend())


def number_as_bytes(number, pad_bits=None):
    """
    Given a number, format as a little endian array of bytes
    """
    result = int_to_bytes(number)[::-1]
    while pad_bits is not None and len(result) < (pad_bits // 8):
        result += b'\x00'
    return result


# @return
#       c               : ciphertext_c
#       iv              : initialization vector
#       key_size        : key size of the RSA private key in bytes.
# @input
#       privkey         : path to the RSA private key
#       priv_key_pass   : path to the RSA privaete key password
#       hmac_key        : HMAC key value ( to calculate DS params)
#       idf_target      : The target chip for the script (e.g. esp32c3)
# @info
#       The function calculates the encrypted private key parameters.
#       Consult the DS documentation (available for the ESP32-S2)
#       in the esp-idf programming guide for more details
#       about the variables and calculations.
def calculate_ds_parameters(privkey, priv_key_pass, hmac_key, idf_target):
    private_key = load_privatekey(privkey, priv_key_pass)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        print('ERROR: Only RSA private keys are supported')
        sys.exit(-1)
    if hmac_key is None:
        print('ERROR: hmac_key cannot be None')
        sys.exit(-2)

    priv_numbers = private_key.private_numbers()
    pub_numbers = private_key.public_key().public_numbers()
    Y = priv_numbers.d
    M = pub_numbers.n
    key_size = private_key.key_size
    if key_size not in supported_key_size[idf_target]:
        print('ERROR: Private key size {0} not supported for the target {1},'
              '\nthe supported key sizes are {2}'
              .format(key_size, idf_target,
                      str(supported_key_size[idf_target])))
        sys.exit(-1)

    iv = os.urandom(16)

    rr = 1 << (key_size * 2)
    rinv = rr % pub_numbers.n
    mprime = - rsa._modinv(M, 1 << 32)
    mprime &= 0xFFFFFFFF
    length = key_size // 32 - 1

    # get max supported key size for the respective target
    max_len = max(supported_key_size[idf_target])
    aes_key = hmac.HMAC(hmac_key, b'\xFF' * 32, hashlib.sha256).digest()

    md_in = number_as_bytes(Y, max_len) + \
        number_as_bytes(M, max_len) + \
        number_as_bytes(rinv, max_len) + \
        struct.pack('<II', mprime, length) + \
        iv

    # expected_len = max_len_Y + max_len_M + max_len_rinv
    #                + (mprime + length packed (8 bytes))+ iv (16 bytes)
    expected_len = (max_len / 8) * 3 + 8 + 16
    assert len(md_in) == expected_len
    md = hashlib.sha256(md_in).digest()
    # In case of ESP32-S2
    # Y4096 || M4096 || Rb4096 || M_prime32 || LENGTH32 || MD256 || 0x08*8
    # In case of ESP32-C3
    # Y3072 || M3072 || Rb3072 || M_prime32 || LENGTH32 || MD256 || 0x08*8
    p = number_as_bytes(Y, max_len) + \
        number_as_bytes(M, max_len) + \
        number_as_bytes(rinv, max_len) + \
        md + \
        struct.pack('<II', mprime, length) + \
        b'\x08' * 8

    # expected_len = max_len_Y + max_len_M + max_len_rinv
    #                + md (32 bytes) + (mprime + length packed (8bytes))
    #                + padding (8 bytes)
    expected_len = (max_len / 8) * 3 + 32 + 8 + 8
    assert len(p) == expected_len

    cipher = Cipher(algorithms.AES(aes_key),
                    modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    c = encryptor.update(p) + encryptor.finalize()
    return c, iv, key_size


# @info
#       The function makes use of the "espefuse.py" script
#       to read the efuse summary
def efuse_summary(args, idf_target):
    os.system('python {0}/components/esptool_py/esptool/espefuse.py '
              '--chip {1} -p {2} summary'
              .format((idf_path), (idf_target), (args.port)))


# @info
#       The function makes use of the "espefuse.py" script to
#       burn the HMAC key on the efuse.
def efuse_burn_key(args, idf_target):
    # In case of a development (default) usecase
    # we dont enable the read protection.
    key_block_status = '--no-read-protect'

    if args.production is True:
        # Whitespace character will have no additional
        # effect on the command and
        # read protection will be enabled as the default
        # behaviour of the command
        key_block_status = ' '
    else:
        print('WARNING:Efuse key block shall not be read '
              'protected in development mode (default)\n'
              'Enable production mode to read protect the key block')
    os.system('python {0}/components/esptool_py/esptool/espefuse.py '
              '--chip {1} -p {2} burn_key '
              '{3} {4} HMAC_DOWN_DIGITAL_SIGNATURE {5}'
              .format((idf_path), (idf_target), (args.port),
                      ('BLOCK_KEY' + str(args.efuse_key_id)),
                      (hmac_key_file), (key_block_status)))


# size is calculated as actual size + 16 (offset)
ciphertext_size = {'esp32s2': 1600, 'esp32s3': 1600, 'esp32c3': 1216}


# @info
#       This function generates the cust_flash partition of
#       the encrypted private key parameters when DS is enabled.
def generate_cust_flash_partition_ds(c, iv, hmac_key_id, key_size,
                                     device_cert, ca_cert,
                                     idf_target, op_file):
    # Following offsets have been calculated with help of
    # esp_secure_cert_config.h
    METADATA_OFFSET = 0
    DEV_CERT_OFFSET = METADATA_OFFSET + 64
    CA_CERT_OFFSET = DEV_CERT_OFFSET + 2048
    CIPHERTEXT_OFFSET = CA_CERT_OFFSET + 4096
    IV_OFFSET = CIPHERTEXT_OFFSET + ciphertext_size[idf_target]

    # cust_flash partition is of size 0x6000 i.e. 24576
    with open(op_file, 'wb') as output_file:
        output_file_data = bytearray(b'\xff' * 24576)
        metadata = b'\x00'
        with open(device_cert, 'rb') as cli_cert:
            dev_cert = cli_cert.read()
            # Write device cert at specific address
            dev_cert = dev_cert + b'\0'
            output_file_data[DEV_CERT_OFFSET: DEV_CERT_OFFSET
                             + len(dev_cert)] = dev_cert
            # The following line packs the dev_cert_crc
            # and dev_cet_len into the metadata in little endian format
            # The value `0xffffffff` corresponds to the
            # starting value used at the time of calculation
            metadata = struct.pack('<IH',
                                   zlib.crc32(dev_cert, 0xffffffff),
                                   len(dev_cert))
            # Align to 32 bit, this is done to match
            # the same operation done by the compiler
            metadata = metadata + b'\x00' * 2

        if ca_cert is not None:
            with open(ca_cert, 'rb') as ca_cert:
                ca_cert = ca_cert.read()
                # Write ca cert at specific address
                ca_cert = ca_cert + b'\0'
                output_file_data[CA_CERT_OFFSET: CA_CERT_OFFSET
                                 + len(ca_cert)] = ca_cert
                metadata = metadata
                + struct.pack('<IH',
                              zlib.crc32(ca_cert, 0xffffffff),
                              len(ca_cert))
        else:
            output_file_data[CA_CERT_OFFSET: CA_CERT_OFFSET] = b'\x00'
            metadata = metadata + struct.pack('<IH', 0, 0)

        # Align to 32 bit
        metadata = metadata + b'\x00' * 2

        # Add ciphertext to the binary
        output_file_data[CIPHERTEXT_OFFSET: CIPHERTEXT_OFFSET + len(c)] = c
        metadata = metadata + struct.pack('<IH',
                                          zlib.crc32(c, 0xffffffff),
                                          len(c))
        # Align to 32 bit
        metadata = metadata + b'\x00' * 2

        # Add iv to the binary
        output_file_data[IV_OFFSET: IV_OFFSET + len(iv)] = iv
        metadata = metadata + struct.pack('<IH',
                                          zlib.crc32(iv, 0xffffffff),
                                          len(iv))
        metadata = metadata + struct.pack('<H', key_size)
        metadata = metadata + struct.pack('<B', hmac_key_id)
        # Align to 32 bit
        metadata = metadata + b'\x00' * 3
        metadata = metadata + struct.pack('<I', 0x12345678)

        # Add metadata to the binary
        output_file_data[METADATA_OFFSET: METADATA_OFFSET + 64] = b'\x00' * 64
        output_file_data[METADATA_OFFSET: METADATA_OFFSET
                         + len(metadata)] = metadata
        output_file.write(output_file_data)
        output_file.close()


# @info
#       This function generates the cust_flash partition of
#       the encrypted private key parameters when DS is disabled.
def generate_cust_flash_partition_no_ds(device_cert, ca_cert,
                                        priv_key, priv_key_pass,
                                        idf_target, op_file):
    # Following offsets have been calculated with help
    # of esp_secure_cert_config.h
    METADATA_OFFSET = 0
    DEV_CERT_OFFSET = METADATA_OFFSET + 64
    CA_CERT_OFFSET = DEV_CERT_OFFSET + 2048
    PRIV_KEY_OFFSET = CA_CERT_OFFSET + 4096

    # cust_flash partition is of size 0x6000 i.e. 24576
    with open(op_file, 'wb') as output_file:
        output_file_data = bytearray(b'\xff' * 24576)
        metadata = b'\x00'
        with open(device_cert, 'rb') as cli_cert:
            dev_cert = cli_cert.read()
            # Write device cert at specific address
            dev_cert = dev_cert + b'\0'
            output_file_data[DEV_CERT_OFFSET: DEV_CERT_OFFSET
                             + len(dev_cert)] = dev_cert
            # The following line packs the dev_cert_crc and dev_cet_len
            # into the metadata in little endian format
            # The value `0xffffffff` corresponds to the starting value
            # used at the time of calculation
            metadata = struct.pack('<IH',
                                   zlib.crc32(dev_cert, 0xffffffff),
                                   len(dev_cert))
            # Align to 32 bit, this is done to match
            # the same operation done by the compiler
            metadata = metadata + b'\x00' * 2

        if ca_cert is not None:
            with open(ca_cert, 'rb') as ca_cert:
                ca_cert = ca_cert.read()
                # Write ca cert at specific address
                ca_cert = ca_cert + b'\0'
                output_file_data[CA_CERT_OFFSET: CA_CERT_OFFSET
                                 + len(ca_cert)] = ca_cert
                metadata = metadata
                + struct.pack('<IH',
                              zlib.crc32(ca_cert, 0xffffffff),
                              len(ca_cert))
        else:
            output_file_data[CA_CERT_OFFSET: CA_CERT_OFFSET] = b'\x00'
            metadata = metadata + struct.pack('<IH', 0, 0)

        # Align to 32 bit
        metadata = metadata + b'\x00' * 2

        private_key = load_privatekey(priv_key, priv_key_pass)

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())

        # Write private key at specific address
        private_key_pem = private_key_pem + b'\0'
        output_file_data[PRIV_KEY_OFFSET: PRIV_KEY_OFFSET
                         + len(private_key_pem)] = private_key_pem
        metadata = metadata
        + struct.pack('<IH',
                      zlib.crc32(private_key_pem, 0xffffffff),
                      len(private_key_pem))
        # Align to 32 bit, this is done to match the
        # same operation done by the compiler
        metadata = metadata + b'\x00' * 2

        metadata = metadata + struct.pack('<I', 0x12345678)

        # Add metadata to the binary
        output_file_data[METADATA_OFFSET: METADATA_OFFSET + 64] = b'\x00' * 64
        output_file_data[METADATA_OFFSET: METADATA_OFFSET
                         + len(metadata)] = metadata
        output_file.write(output_file_data)
        output_file.close()


# @info
#       Generate a custom csv file of encrypted private key parameters
#       when DS is enabled.
#       The csv file is required by the nvs_partition_generator
#       utility to create the nvs partition.
def generate_csv_file_ds(c, iv, hmac_key_id, key_size,
                         device_cert, ca_cert, csv_file):

    with open(csv_file, 'wt', encoding='utf8') as f:
        f.write('# This is a generated csv file containing '
                'required parameters for the Digital Signature operation\n')
        f.write('key,type,encoding,value\nesp_secure_cert,namespace,,\n')

        if ca_cert is not None:
            f.write('ca_cert,file,string,{}\n'.format(ca_cert))
        f.write('cipher_c,data,hex2bin,{}\n'.format(c.hex()))
        f.write('dev_cert,file,string,{}\n'.format(device_cert))
        f.write('rsa_len,data,u16,{}\n'.format(key_size))
        f.write('ds_key_id,data,u8,{}\n'.format(hmac_key_id))
        f.write('iv,data,hex2bin,{}\n'.format(iv.hex()))


# @info
#       Generate a custom csv file of encrypted private key parameters
#       when DS is disabled.
#       The csv file is required by the nvs_partition_generator utility
#       to create the nvs partition.
def generate_csv_file_no_ds(device_cert, ca_cert, priv_key,
                            priv_key_pass, csv_file):

    with open(csv_file, 'wt', encoding='utf8') as f:
        f.write('# This is a generated csv file containing required '
                'parameters for the Digital Signature operation\n')
        f.write('key,type,encoding,value\nesp_secure_cert,namespace,,\n')

        if ca_cert is not None:
            f.write('ca_cert,file,string,{}\n'.format(ca_cert))
        f.write('dev_cert,file,string,{}\n'.format(device_cert))

        private_key = load_privatekey(priv_key, priv_key_pass)

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())

        f.write('priv_key,data,string,{}\n'.format(private_key_pem.decode()))


class DefineArgs(object):
    def __init__(self, attributes):
        for key, value in attributes.items():
            self.__setattr__(key, value)


# @info
#       This function uses the nvs_partition_generater utility
#       to generate the nvs partition of the encrypted private key parameters.
def generate_nvs_partition(input_filename, output_filename):

    nvs_args = DefineArgs({
        'input': input_filename,
        'outdir': os.getcwd(),
        'output': output_filename,
        'size': hex(0x3000),
        'version': 2,
        'keyfile': None,
    })

    nvs_gen.generate(nvs_args, is_encr_enabled=False, encr_key=None)


# @return
#         The json formatted summary of the efuse.
def get_efuse_summary_json(args, idf_target):
    _efuse_summary = None
    try:
        _efuse_summary = subprocess.check_output(
                ('python {0}/components/esptool_py/esptool/espefuse.py '
                 '--chip {1} -p {2} summary --format json'
                 .format((idf_path), (idf_target), (args.port))), shell=True)
    except subprocess.CalledProcessError as e:
        print((e.output).decode('UTF-8'))
        sys.exit(-1)

    _efuse_summary = _efuse_summary.decode('UTF-8')
    # Remove everything before actual json data from
    # efuse_summary command output.
    _efuse_summary = _efuse_summary[_efuse_summary.find('{'):]
    try:
        _efuse_summary_json = json.loads(_efuse_summary)
    except json.JSONDecodeError:
        print('ERROR: failed to parse the json output')
        sys.exit(-1)
    return _efuse_summary_json


# @return
#       on success: 256 bit HMAC key present in the given key_block
#                   (args.efuse_key_id)
#       on failure: None
# @info
#       This function configures the provided efuse key_block.
#       If the provided efuse key_block is empty the function generates
#       a new HMAC key and burns it in the efuse key_block.
#       If the key_block already contains a key the function reads
#       the key from the efuse key_block
def configure_efuse_key_block(args, idf_target):
    efuse_summary_json = get_efuse_summary_json(args, idf_target)
    key_blk = 'BLOCK_KEY' + str(args.efuse_key_id)
    key_purpose = 'KEY_PURPOSE_' + str(args.efuse_key_id)

    kb_writeable = efuse_summary_json[key_blk]['writeable']
    kb_readable = efuse_summary_json[key_blk]['readable']
    hmac_key_read = None

    # If the efuse key block is writable (empty) then generate and write
    # the new hmac key and check again
    # If the efuse key block is not writable (already contains a key)
    # then check if it is readable
    if kb_writeable is True:
        print('Provided key block (KEY BLOCK {}) is writable\n'
              'Generating a new key and burning it in the efuse..\n'
              .format(args.efuse_key_id))

        new_hmac_key = os.urandom(32)
        with open(hmac_key_file, 'wb') as key_file:
            key_file.write(new_hmac_key)
        # Burn efuse key
        efuse_burn_key(args, idf_target)
        if args.production is False:
            # Read fresh summary of the efuse to read the
            # key value from efuse.
            # If the key read from efuse matches with the key generated
            # on host then burn_key operation was successfull
            new_efuse_summary_json = get_efuse_summary_json(args, idf_target)
            hmac_key_read = new_efuse_summary_json[key_blk]['value']
            print(hmac_key_read)
            hmac_key_read = bytes.fromhex(hmac_key_read)
            if new_hmac_key == hmac_key_read:
                print('Key was successfully written to the efuse '
                      '(KEY BLOCK {})'.format(args.efuse_key_id))
            else:
                print('ERROR: Failed to burn the hmac key to efuse '
                      '(KEY BLOCK {}),'
                      '\nPlease execute the script again using '
                      'a different key id'.format(args.efuse_key_id))
                return None
        else:
            new_efuse_summary_json = get_efuse_summary_json(args, idf_target)
            if (new_efuse_summary_json[key_purpose]['value']
                    != 'HMAC_DOWN_DIGITAL_SIGNATURE'):
                print('ERROR: Failed to verify the key purpose of '
                      'the key block{})'.format(args.efuse_key_id))
                return None
            hmac_key_read = new_hmac_key
    else:
        # If the efuse key block is redable, then read the key from
        # efuse block and use it for encrypting the RSA private key parameters.
        # If the efuse key block is not redable or it has key
        # purpose set to a different value than "HMAC_DOWN_DIGITAL_SIGNATURE"
        # then we cannot use it for DS operation
        if kb_readable is True:
            if (efuse_summary_json[key_purpose]['value'] ==
                    'HMAC_DOWN_DIGITAL_SIGNATURE'):
                print('Provided efuse key block (KEY BLOCK {}) '
                      'already contains a key with '
                      'key_purpose=HMAC_DOWN_DIGITAL_SIGNATURE,'
                      '\nusing the same key for encrypting the '
                      'private key data...\n'.format(args.efuse_key_id))
                hmac_key_read = efuse_summary_json[key_blk]['value']
                hmac_key_read = bytes.fromhex(hmac_key_read)
                if args.keep_ds_data is True:
                    with open(hmac_key_file, 'wb') as key_file:
                        key_file.write(hmac_key_read)
            else:
                print('ERROR: Provided efuse key block ((KEY BLOCK {})) '
                      'contains a key with key purpose different '
                      'than HMAC_DOWN_DIGITAL_SIGNATURE,'
                      '\nplease execute the script again with '
                      'a different value of the efuse key id.'
                      .format(args.efuse_key_id))
                return None
        else:
            print('ERROR: Provided efuse key block (KEY BLOCK {}) '
                  'is not readable and writeable,'
                  '\nplease execute the script again '
                  'with a different value of the efuse key id.'
                  .format(args.efuse_key_id))
            return None

    # Return the hmac key burned into the efuse
    return hmac_key_read


def cleanup(args):
    if args.keep_ds_data is False:
        if os.path.exists(hmac_key_file):
            os.remove(hmac_key_file)
        if os.path.exists(csv_filename):
            os.remove(csv_filename)


def main():
    parser = argparse.ArgumentParser(description='''
    Generate an HMAC key and burn it in the desired efuse key
    block (required for Digital Signature),
    Generates an NVS partition containing the
    encrypted private key parameters from the client private key.''')

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
        default='client.crt',
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
        '--secure_cert_type',
        dest='sec_cert_type', type=str, choices={'cust_flash', 'nvs'},
        default='cust_flash',
        metavar='type of secure_cert partition',
        help='The type of esp_secure_cert partition. '
             'Can be \"cust_flash\" or \"nvs\"')

    parser.add_argument(
        '--target_chip',
        dest='target_chip', type=str,
        choices={'esp32s2', 'esp32s3', 'esp32c3'},
        default='esp32c3',
        metavar='target chip',
        help='The target chip e.g. esp32s2, s3, c3')

    parser.add_argument(
        '--summary',
        dest='summary', action='store_true',
        help='Provide this option to print efuse summary of the chip')

    parser.add_argument(
        '--configure_ds',
        dest='configure_ds', action='store_true',
        help='Provide this option to configure the DS peripheral.')

    parser.add_argument(
        '--efuse_key_id',
        dest='efuse_key_id', type=int, choices=range(1, 6),
        metavar='[key_id] ',
        default=1,
        help='Provide the efuse key_id which '
             'contains/will contain HMAC_KEY, default is 1')

    parser.add_argument(
        '--port', '-p',
        dest='port',
        metavar='[port]',
        required=True,
        help='UART com port to which the ESP device is connected')

    parser.add_argument(
        '--keep_ds_data_on_host', '-keep_ds_data',
        dest='keep_ds_data', action='store_true',
        help='Keep encrypted private key data and key '
             'on host machine for testing purpose')

    parser.add_argument(
        '--production', '-prod',
        dest='production', action='store_true',
        help='Enable production configurations. '
             'e.g.keep efuse key block read protection enabled')

    args = parser.parse_args()

    idf_target = args.target_chip
    if idf_target not in supported_targets:
        if idf_target is not None:
            print('ERROR: The script does not support '
                  'the target {}'.format(idf_target))
        sys.exit(-1)
    idf_target = str(idf_target)

    if args.summary is not False:
        efuse_summary(args, idf_target)
        sys.exit(0)

    if (os.path.exists(args.privkey) is False):
        print('ERROR: The provided private key file does not exist')
        sys.exit(-1)

    if (os.path.exists(args.device_cert) is False):
        print('ERROR: The provided client cert file does not exist')
        sys.exit(-1)

    if (os.path.exists(esp_ds_data_dir) is False):
        os.makedirs(esp_ds_data_dir)

    # Provide CA cert path only if it exists
    ca_cert = None
    if (os.path.exists(args.ca_cert) is True):
        ca_cert = args.ca_cert

    c = None
    iv = None
    key_size = None

    if args.configure_ds is not False:
        # Burn hmac_key on the efuse block (if it is empty) or read it
        # from the efuse block (if the efuse block already contains a key).
        hmac_key_read = configure_efuse_key_block(args, idf_target)
        if hmac_key_read is None:
            sys.exit(-1)

        # Calculate the encrypted private key data along
        # with all other parameters
        c, iv, key_size = calculate_ds_parameters(args.privkey,
                                                  args.priv_key_pass,
                                                  hmac_key_read, idf_target)
    else:
        print('--configure_ds option not set. '
              'Configuring without use of DS peripheral.')
        print('WARNING: Not Secure.\n'
              'the private shall be stored as plaintext')

    if args.sec_cert_type == 'cust_flash':
        if args.configure_ds is not False:
            generate_cust_flash_partition_ds(c, iv, args.efuse_key_id,
                                             key_size, args.device_cert,
                                             ca_cert, idf_target,
                                             bin_filename)
        else:
            generate_cust_flash_partition_no_ds(args.device_cert, ca_cert,
                                                args.privkey,
                                                args.priv_key_pass,
                                                idf_target, bin_filename)
    elif args.sec_cert_type == 'nvs':
        # Generate csv file for the DS data and generate an NVS partition.
        if args.configure_ds is not False:
            generate_csv_file_ds(c, iv, args.efuse_key_id,
                                 key_size, args.device_cert,
                                 ca_cert, csv_filename)
        else:
            generate_csv_file_no_ds(args.device_cert, ca_cert,
                                    args.privkey, args.priv_key_pass,
                                    csv_filename)
        generate_nvs_partition(csv_filename, bin_filename)

    cleanup(args)


if __name__ == '__main__':
    main()
