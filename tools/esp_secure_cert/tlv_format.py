import sys
import enum
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


class tlv_type_t(enum.IntEnum):
    CA_CERT = 0
    DEV_CERT = 1
    PRIV_KEY = 2
    DS_DATA = 3
    DS_CONTEXT = 4
    TLV_END = 50
    USER_DATA_1 = 51
    USER_DATA_2 = 52
    USER_DATA_3 = 53
    USER_DATA_4 = 54
    USER_DATA_5 = 55


# This is the minimum required flash address alignment to write
# to an encrypted partition on esp device
MIN_ALIGNMENT_REQUIRED = 16


def prepare_tlv(tlv_type, data, data_len):
    # Add the magic at start ( unsigned int )
    tlv_header = struct.pack('<I', 0xBA5EBA11)
    # Reserved bytes in TLV header ( 4 bytes)
    tlv_header = tlv_header + struct.pack('<I', 0x00000000)
    # Add the tlv type ( unsigned short )
    tlv_header = tlv_header + struct.pack('<H', tlv_type)
    # Add the data_length ( unsigned short )
    tlv_header = tlv_header + struct.pack('<H', data_len)
    tlv = tlv_header + data
    # Add padding after data and before the footer
    padding_len = MIN_ALIGNMENT_REQUIRED - (len(data) % MIN_ALIGNMENT_REQUIRED)

    padding_len = 0 if padding_len == MIN_ALIGNMENT_REQUIRED else padding_len
    tlv = tlv + b'\x00' * padding_len
    # Add the crc value ( unsigned int )
    # The value `0xffffffff` corresponds to the
    # starting value used at the time of calculation
    tlv_footer = struct.pack('<I', zlib.crc32(tlv, 0xffffffff))
    tlv = tlv + tlv_footer
    return tlv


# @info
#       This function generates the cust_flash partition of
#       the encrypted private key parameters when DS is enabled.
def generate_partition_ds(c, iv, hmac_key_id, key_size,
                          device_cert, ca_cert, idf_target,
                          op_file):
    # cust_flash partition is of size 0x2000 i.e. 8192 bytes
    tlv_data_length = 0
    with open(op_file, 'wb') as output_file:
        partition_size = 0x2000
        output_file_data = bytearray(b'\xff' * partition_size)
        cur_offset = 0
        with open(device_cert, 'rb') as cli_cert:
            dev_cert = cli_cert.read()
            # Null terminate the dev_cert.
            dev_cert = dev_cert + b'\0'
            dev_cert_tlv = prepare_tlv(tlv_type_t.DEV_CERT,
                                       dev_cert,
                                       len(dev_cert))
            output_file_data[cur_offset: cur_offset
                             + len(dev_cert_tlv)] = dev_cert_tlv
            cur_offset = cur_offset + len(dev_cert_tlv)
            print('dev_cert tlv: total length = {}'.format(len(dev_cert_tlv)))
            tlv_data_length += len(dev_cert_tlv)

        if ca_cert is not None:
            with open(ca_cert, 'rb') as ca_cert:
                ca_cert = ca_cert.read()
                # Write ca cert at specific address
                ca_cert = ca_cert + b'\0'
                ca_cert_tlv = prepare_tlv(tlv_type_t.CA_CERT,
                                          ca_cert,
                                          len(ca_cert))
                output_file_data[cur_offset: cur_offset
                                 + len(ca_cert_tlv)] = ca_cert_tlv
                cur_offset = cur_offset + len(ca_cert_tlv)
                print('ca_cert tlv: total length = {}'
                      .format(len(ca_cert_tlv)))
                tlv_data_length += len(ca_cert_tlv)

        # create esp_secure_cert_data struct
        ds_data = struct.pack('<i', key_size // 32 - 1)
        ds_data = ds_data + iv
        ds_data = ds_data + c

        ds_data_tlv = prepare_tlv(tlv_type_t.DS_DATA, ds_data, len(ds_data))
        output_file_data[cur_offset: cur_offset
                         + len(ds_data_tlv)] = ds_data_tlv
        cur_offset = cur_offset + len(ds_data_tlv)
        print('ds_data tlv: total length = {}'.format(len(ds_data_tlv)))
        tlv_data_length += len(ds_data_tlv)

        # create ds_context struct
        ds_context = struct.pack('<I', 0)
        ds_context = ds_context + struct.pack('<B', hmac_key_id)
        # Add padding to match the compiler
        ds_context = ds_context + struct.pack('<B', 0)
        ds_context = ds_context + struct.pack('<H', key_size)

        ds_context_tlv = prepare_tlv(tlv_type_t.DS_CONTEXT,
                                     ds_context,
                                     len(ds_context))
        output_file_data[cur_offset: cur_offset
                         + len(ds_context_tlv)] = ds_context_tlv
        cur_offset = cur_offset + len(ds_context_tlv)
        print('ds_context tlv: total length = {}'.format(len(ds_context_tlv)))
        tlv_data_length += len(ds_context_tlv)
        print('Total length of tlv data = {}'.format(tlv_data_length))
        output_file.write(output_file_data)
        output_file.close()


# @info
#       This function generates the cust_flash partition of
#       the encrypted private key parameters when DS is disabled.
def generate_partition_no_ds(device_cert, ca_cert, priv_key,
                             priv_key_pass, idf_target, op_file):
    # cust_flash partition is of size 0x2000 i.e. 8192 bytes
    tlv_data_length = 0
    with open(op_file, 'wb') as output_file:
        partition_size = 0x2000
        output_file_data = bytearray(b'\xff' * partition_size)
        cur_offset = 0
        with open(device_cert, 'rb') as cli_cert:
            cur_offset = 0
            dev_cert = cli_cert.read()
            # Null terminate the dev_cert.
            dev_cert = dev_cert + b'\0'
            dev_cert_tlv = prepare_tlv(tlv_type_t.DEV_CERT,
                                       dev_cert,
                                       len(dev_cert))
            output_file_data[cur_offset: cur_offset
                             + len(dev_cert_tlv)] = dev_cert_tlv
            cur_offset = cur_offset + len(dev_cert_tlv)
            print('dev_cert tlv: total length = {}'.format(len(dev_cert_tlv)))
            tlv_data_length += len(dev_cert_tlv)

        if ca_cert is not None:
            with open(ca_cert, 'rb') as ca_cert:
                ca_cert = ca_cert.read()
                # Write ca cert at specific address
                ca_cert = ca_cert + b'\0'
                ca_cert_tlv = prepare_tlv(tlv_type_t.CA_CERT,
                                          ca_cert,
                                          len(ca_cert))
                output_file_data[cur_offset: cur_offset
                                 + len(ca_cert_tlv)] = ca_cert_tlv
                cur_offset = cur_offset + len(ca_cert_tlv)
                print('ca_cert tlv: total length = {}'
                      .format(len(ca_cert_tlv)))
                tlv_data_length += len(ca_cert_tlv)

        private_key = load_privatekey(priv_key, priv_key_pass)

        # Write private key at specific address
        private_key = private_key + b'\0'
        priv_key_tlv = prepare_tlv(tlv_type_t.PRIV_KEY,
                                   private_key,
                                   len(private_key))
        output_file_data[cur_offset: cur_offset
                         + len(priv_key_tlv)] = priv_key_tlv
        print('priv_key tlv: total length = {}'.format(len(priv_key_tlv)))
        tlv_data_length += len(priv_key_tlv)
        print('Total length of tlv data = {}'.format(tlv_data_length))
        output_file.write(output_file_data)
        output_file.close()
