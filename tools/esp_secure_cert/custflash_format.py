import sys
import struct
import zlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def load_privatekey(key_file_path, password=None):
    with open(key_file_path, 'rb') as key_file:
        key = key_file.read()

    try:
        private_key = serialization.load_pem_private_key(key, password=password, backend=default_backend())
        return private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PrivateFormat.TraditionalOpenSSL,
                                         encryption_algorithm=serialization.NoEncryption())
    except ValueError:
        pass

    try:
        private_key = serialization.load_der_private_key(key, password=password, backend=default_backend())
        return private_key.private_bytes(encoding=serialization.Encoding.DER,
                                         format=serialization.PrivateFormat.TraditionalOpenSSL,
                                         encryption_algorithm=serialization.NoEncryption())
    except ValueError:
        print("Unsupported key encoding format, Please provide PEM or DER encoded key", file=sys.stderr)
        sys.exit(1)


# size is calculated as actual size + 16 (offset)
ciphertext_size = {'esp32s2': 1600, 'esp32s3': 1600, 'esp32c3': 1216}


# @info
#       This function generates the cust_flash partition of
#       the encrypted private key parameters when DS is enabled.
def generate_partition_ds(c, iv, hmac_key_id, key_size,
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
                metadata += struct.pack('<IH',
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
def generate_partition_no_ds(device_cert, ca_cert,
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
                metadata += struct.pack('<IH',
                                        zlib.crc32(ca_cert, 0xffffffff),
                                        len(ca_cert))
        else:
            output_file_data[CA_CERT_OFFSET: CA_CERT_OFFSET] = b'\x00'
            metadata = metadata + struct.pack('<IH', 0, 0)

        # Align to 32 bit
        metadata = metadata + b'\x00' * 2

        private_key = load_privatekey(priv_key, priv_key_pass)

        # Write private key at specific address
        private_key = private_key + b'\0'
        output_file_data[PRIV_KEY_OFFSET: PRIV_KEY_OFFSET
                         + len(private_key)] = private_key
        metadata += struct.pack('<IH',
                                zlib.crc32(private_key, 0xffffffff),
                                len(private_key))
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
