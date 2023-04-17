import os
import subprocess
import sys
import json
from typing import Union


def get_efuse_summary_json(idf_path: str,
                           idf_target: str, port: str) -> dict:
    """
    Executes an 'espefuse' command to obtain
    eFuse summary in JSON format.

    Args:
        idf_path (str): Path to the ESP-IDF installation directory.
        idf_target (str): ESP-IDF target to build for.
        port (str): Serial port to communicate with the device.

    Returns:
        dict: A dictionary containing eFuse summary data in JSON format.

    Raises:
        subprocess.CalledProcessError: If the 'espefuse' command exits
        with a non-zero status.
        json.JSONDecodeError: If the eFuse summary output
        cannot be parsed as JSON.
    """
    efuse_summary = None
    try:
        efuse_summary = subprocess.check_output(
            f"python {idf_path}/components/esptool_py/esptool/espefuse.py "
            f"--chip {idf_target} -p {port} summary --format json",
            shell=True
        )
    except subprocess.CalledProcessError as e:
        print(e.output.decode("utf-8"))
        sys.exit(-1)

    efuse_summary = efuse_summary.decode("utf-8")
    # Remove everything before actual json data
    # from efuse_summary command output.
    efuse_summary = efuse_summary[efuse_summary.find("{"):]
    try:
        efuse_summary_json = json.loads(efuse_summary)
        return efuse_summary_json
    except json.JSONDecodeError:
        raise json.JSONDecodeError("Failed to parse the "
                                   "eFuse summary JSON output")


def log_efuse_summary(idf_path: str, idf_target: str, port: str) -> None:
    """
    Prints the efuse summary on console by executing the `espefuse.py` script.

    Args:
        idf_path (str): Path to the IDF installation directory.
        idf_target (str): IDF target chip.
        port (str): Serial port to use for communication with the chip.

    Returns:
        None

    Raises:
        OSError: If there is an issue executing the `espefuse.py` script.
    """
    try:
        os.system(f"python {idf_path}/components/esptool_py/esptool/"
                  f"espefuse.py --chip {idf_target} -p {port} summary")
    except OSError:
        raise OSError("Unable to execute `espefuse.py` script")


def efuse_burn_key(idf_path: str, idf_target: str, port: str,
                   efuse_key_file: str, efuse_key_id: int,
                   efuse_purpose: str, production: bool):
    """
    Burns an HMAC key to the efuse using the "espefuse.py" script.

    Args:
        idf_path (str): Path to the ESP-IDF directory.
        idf_target (str): Target chip of the ESP-IDF build.
        port (str): Serial port to use.
        efuse_key_file (str): Path to the key file.
        efuse_key_id (int): The eFuse key id to use for burning the key.
        efuse_purpose (str): The purpose to be set for the eFuse key block
        production (bool): If True, read protection
        will be enabled by default.

    Raises:
        FileNotFoundError: If the key file cannot be found or read.
    """
    # In case of a development (default) usecase
    # we dont enable the read protection.
    key_block_status = '--no-read-protect'

    if production:
        # Whitespace character will have no additional
        # effect on the command and
        # read protection will be enabled as the default
        # behaviour of the command
        key_block_status = ' '
    else:
        print('WARNING:Efuse key block shall not be read '
              'protected in development mode (default)\n'
              'Enable production mode to read protect the key block')

    if not os.path.isfile(efuse_key_file):
        raise FileNotFoundError(f"Key file not found: {efuse_key_file}")

    os.system(f'python {idf_path}/components/esptool_py/esptool/espefuse.py '
              f'--chip {idf_target} -p {port} burn_key '
              f'BLOCK_KEY{efuse_key_id} {efuse_key_file} {efuse_purpose}'
              f' {key_block_status}')


def configure_efuse_key_block(idf_path: str, idf_target: str, port: str,
                              efuse_key_file: str, efuse_key_id: int,
                              efuse_purpose: str,
                              production: bool) -> Union[bytes, None]:
    """
    Configures the provided efuse key_block.

    If the provided efuse key_block is empty the function generates
    a new HMAC key and burns it in the efuse key_block.
    If the key_block already contains a key the function reads
    the key from the efuse key_block

    Args:
        idf_path (str): Path to the ESP-IDF directory.
        idf_target (str): Target chip of the ESP-IDF build.
        port (str): Serial port to use.
        efuse_key_file (str): Path to the key file.
        efuse_key_id (int): The eFuse key id to use for burning the key.
        efuse_purpose (str): The purpose to be set for the eFuse key block.
        production (bool): If True, read protection will be enabled by default.

    Returns:
        bytes: 256-bit key written in the given
               key_block (efuse_key_id) if successful.
               If key is already burned and is readable
               then this API returns the same key
        None: If the operation fails.
    """
    efuse_summary_json = get_efuse_summary_json(idf_path, idf_target, port)
    key_blk = 'BLOCK_KEY' + str(efuse_key_id)
    key_purpose = 'KEY_PURPOSE_' + str(efuse_key_id)

    kb_writeable = efuse_summary_json[key_blk]['writeable']
    kb_readable = efuse_summary_json[key_blk]['readable']
    efuse_key_read = None

    # If the efuse key block is writable (empty) then generate and write
    # the new hmac key and check again
    # If the efuse key block is not writable (already contains a key)
    # then check if it is readable
    if kb_writeable is True:
        print(f'Provided key block (KEY BLOCK {efuse_key_id}) is writable\n'
              f'Generating a new key and burning it in the efuse..\n')

        if os.path.exists(efuse_key_file):
            print('Key file present, using the same key')
            with open(efuse_key_file, 'wb') as key_file:
                new_efuse_key = key_file.read()
                if len(new_efuse_key) != 32:
                    print(f'The key present at {efuse_key_file} is not of'
                          f'length 256 bits\n'
                          f'Generating a new key and '
                          f'overwriting the existing key')

                    new_efuse_key = os.urandom(32)
                    key_file.write(new_efuse_key)
                else:
                    print('Using the provided key')
        else:
            new_efuse_key = os.urandom(32)
            with open(efuse_key_file, 'wb') as key_file:
                key_file.write(new_efuse_key)

        # Burn efuse key
        efuse_burn_key(idf_path, idf_target, port, efuse_key_file,
                       efuse_key_id, efuse_purpose, production)

        # delete the file in case of production mode
        if production:
            if os.path.exists(efuse_key_file):
                os.remove(efuse_key_file)

        if production is False:
            # Read fresh summary of the efuse to read the
            # key value from efuse.
            # If the key read from efuse matches with the key generated
            # on host then burn_key operation was successful
            new_efuse_summary_json = get_efuse_summary_json(idf_path,
                                                            idf_target,
                                                            port)
            efuse_key_read = new_efuse_summary_json[key_blk]['value']
            print(efuse_key_read)
            efuse_key_read = bytes.fromhex(efuse_key_read)
            if new_efuse_key == efuse_key_read:
                print(f'Key was successfully written to the efuse '
                      f'(KEY BLOCK {efuse_key_id})')
            else:
                print(f'ERROR: Failed to burn the hmac key to efuse '
                      f'(KEY BLOCK {efuse_key_id}),'
                      f'\nPlease execute the script again using '
                      f'a different key id')
                return None
        else:
            new_efuse_summary_json = get_efuse_summary_json(idf_path,
                                                            idf_target,
                                                            port)
            if (new_efuse_summary_json[key_purpose]['value']
                    != efuse_purpose):
                print(f'ERROR: Failed to verify the key purpose of '
                      f'the key block{efuse_key_id})')
                return None
            efuse_key_read = new_efuse_key
    else:
        # If the efuse key block is readable, then read the key from
        # efuse block and provide it as the return argument
        # If the efuse key block is not readable or it has key
        # purpose set to a different value than given efuse_purpose
        # then we cannot use it for DS operation
        if kb_readable is True:
            if (efuse_summary_json[key_purpose]['value'] ==
                    efuse_purpose):
                print(f'Provided efuse key block (KEY BLOCK {efuse_key_id}) '
                      f'already contains a key with '
                      f'key_purpose={efuse_purpose},'
                      f'\nusing the same key for encrypting the '
                      f'private key data...\n'.format(efuse_key_id,
                                                      efuse_purpose))
                efuse_key_read = efuse_summary_json[key_blk]['value']
                efuse_key_read = bytes.fromhex(efuse_key_read)

            else:
                print(f'ERROR: Provided efuse key block'
                      f'((KEY BLOCK {efuse_key_id})) '
                      f'contains a key with key purpose different '
                      f'than {efuse_purpose},'
                      f'\nplease execute the script again with '
                      f'a different value of the efuse key id.')
                return None
        else:
            print(f'ERROR: Provided efuse key block (KEY BLOCK {efuse_key_id})'
                  f' is not readable and writeable,'
                  f'\nplease execute the script again '
                  f'with a different value of the efuse key id.')
            return None
    return efuse_key_read
