import hashlib
import hmac
import os
import struct
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.utils import int_to_bytes
from esp_secure_cert.esp_secure_cert_helper import load_private_key
from esp_secure_cert.efuse_helper import (
    log_efuse_summary,
    configure_efuse_key_block,
)
from esp_secure_cert.esp_secure_cert_helper import convert_der_key_to_pem

supported_targets_rsa_ds = ['esp32s2', 'esp32s3', 'esp32c3',
                            'esp32c6', 'esp32h2', 'esp32p4']
supported_key_size_rsa = {'esp32s2': [1024, 2048, 3072, 4096],
                          'esp32c3': [1024, 2048, 3072],
                          'esp32s3': [1024, 2048, 3072, 4096],
                          'esp32c6': [1024, 2048, 3072],
                          'esp32h2': [1024, 2048, 3072],
                          'esp32p4': [1024, 2048, 3072, 4096]}

supported_targets_ecdsa = ['esp32h2', 'esp32p4']
supported_key_size_ecdsa = {'esp32h2': [256],
                            'esp32p4': [256]}

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
def calculate_rsa_ds_params(privkey, priv_key_pass, hmac_key, idf_target):
    private_key_data = load_private_key(privkey, priv_key_pass)
    private_key = private_key_data["key_instance"]
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
    if key_size not in supported_key_size_rsa[idf_target]:
        print('ERROR: Private key size {0} not supported for the target {1},'
              '\nthe supported key sizes are {2}'
              .format(key_size, idf_target,
                      str(supported_key_size_rsa[idf_target])))
        sys.exit(-1)

    iv = os.urandom(16)

    rr = 1 << (key_size * 2)
    rinv = rr % pub_numbers.n
    mprime = - rsa._modinv(M, 1 << 32)
    mprime &= 0xFFFFFFFF
    length = key_size // 32 - 1

    # get max supported key size for the respective target
    max_len = max(supported_key_size_rsa[idf_target])
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


def validate_ds_algorithm(ds_algo, key_size_bits, target_chip):
    if ds_algo == 'RSA':
        if target_chip not in supported_targets_rsa_ds:
            print(f'ERROR: Target {target_chip} does not '
                  'support RSA DS peripheral')
            sys.exit(-1)
        key_size_bits = int(key_size_bits, 10)
        if key_size_bits not in supported_key_size_rsa[target_chip]:
            print(f'ERROR: Target {target_chip} does not support '
                  f'{ds_algo} {key_size_bits}, supported key sizes are '
                  f'{supported_key_size_rsa[target_chip]}')
            sys.exit(-1)

    elif ds_algo == 'ECDSA':
        if target_chip not in supported_targets_ecdsa:
            print(f'ERROR: Target {target_chip} does not support '
                  'ECDSA peripheral')
            sys.exit(-1)

        key_size_bits = int(key_size_bits, 10)
        if key_size_bits not in supported_key_size_ecdsa[target_chip]:
            print(f'ERROR: Target {target_chip} does not support '
                  f'{ds_algo} {key_size_bits}, supported key sizes are '
                  f'{supported_key_size_ecdsa[target_chip]}')
            sys.exit(-1)

    else:
        print(f'ERROR: Invalid DS algorithm {ds_algo} {key_size_bits}')
        sys.exit(-1)


# Returns ecdsa key bytearray
def get_ecdsa_key_bytes(privkey, priv_key_pass, key_length_bytes):
    private_key_data = load_private_key(privkey, priv_key_pass)
    private_key = private_key_data["key_instance"]
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        print('ERROR: Invalid private key format.'
              ' Only ECC private keys are supported')
        sys.exit(-1)
    key_length_bits = key_length_bytes * 8
    if (private_key.key_size != key_length_bits):
        print(f'ERROR: key size {private_key.key_size} does not match'
              f' with required key size {key_length_bytes}')
        sys.exit(-1)

    priv_numbers = private_key.private_numbers()
    private = priv_numbers.private_value
    ecdsa_key = private.to_bytes(key_length_bytes, byteorder='big')
    return ecdsa_key


def configure_efuse_for_rsa(idf_target, port, hmac_key_file, efuse_key_file, rsa_key_size, priv_key, priv_key_pass, efuse_key_id):
    sign_algo = 'RSA'
    sign_algo_key_size = rsa_key_size
    validate_ds_algorithm(sign_algo, sign_algo_key_size, idf_target)

    # Burn hmac_key on the efuse block (if it is empty) or read it
    # from the efuse block (if the efuse block already contains a key).
    efuse_purpose = 'HMAC_DOWN_DIGITAL_SIGNATURE'
    hmac_key = None
    if (efuse_key_file is None or not os.path.exists(efuse_key_file)):
        if not os.path.exists(hmac_key_file):
            hmac_key = os.urandom(32)
            with open(hmac_key_file, "wb+") as key_file:
                key_file.write(hmac_key)

        efuse_key_file = hmac_key_file
    else:
        with open(efuse_key_file, "rb") as key_file:
            hmac_key = key_file.read()

        print(f'Using the eFuse key given at {efuse_key_file}'
                      'as the HMAC key')

    configure_efuse_key_block(idf_target, port, efuse_key_file, efuse_key_id, efuse_purpose)

    with open(efuse_key_file, "rb") as key_file:
        hmac_key = key_file.read()

    return hmac_key

def configure_efuse_for_ecdsa(idf_target, port, ecdsa_key_file, efuse_key_file, esp_secure_cert_data_dir, ecdsa_key_size, priv_key, priv_key_pass, efuse_key_id):
    sign_algo = 'ECDSA'
    sign_algo_key_size = ecdsa_key_size
    validate_ds_algorithm(sign_algo, sign_algo_key_size, idf_target)

    # efuse key length
    expected_key_len = 32
    ecdsa_key = get_ecdsa_key_bytes(priv_key, priv_key_pass, expected_key_len)

    with open(ecdsa_key_file, "wb+") as key_file:
        key_file.write(ecdsa_key)

        temp_ecdsa_key_file = os.path.join(esp_secure_cert_data_dir, 'temp_ecdsa_key.pem')
        try:
           pem_key = convert_der_key_to_pem(priv_key)

           with open(temp_ecdsa_key_file, "wb+") as key_file:
               key_file.write(pem_key)

           efuse_key_file = temp_ecdsa_key_file
           efuse_purpose = 'ECDSA_KEY'

           configure_efuse_key_block(idf_target, port, efuse_key_file, efuse_key_id, efuse_purpose)
        except OSError:
                print('Hint: For ECDSA peripheral esptool version'
                      ' must be >= v4.6, Please make sure the '
                      'requirement is satisfied')
                raise
        finally:
                if os.path.exists(temp_ecdsa_key_file):
                    os.remove(temp_ecdsa_key_file)
