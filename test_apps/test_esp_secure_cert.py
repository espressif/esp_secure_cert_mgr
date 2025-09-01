import pytest
import os
import glob
import hashlib


PARTITION_TABLE_OFFSET = 0xC000
SECURE_CERT_OFFSET = 0xD000


def write_bin_to_flash_image(dut, bin_path, offset):
    """Write binary data to flash image at specified offset using file
    operations"""
    flash_image_bin = os.path.join(dut.app.binary_path, 'flash_image.bin')
    assert os.path.exists(flash_image_bin), (
        f"Flash image not found: {flash_image_bin}"
    )

    # Read the binary data to be written
    with open(bin_path, 'rb') as f:
        data_to_write = f.read()

    # Read the current flash image
    with open(flash_image_bin, 'rb') as f:
        flash_data = bytearray(f.read())

    # Ensure flash image is large enough
    required_size = offset + len(data_to_write)
    if len(flash_data) < required_size:
        assert False, (
            f"Flash image is too small: {len(flash_data)} < {required_size}"
        )

    # Write the data at the specified offset
    flash_data[offset:offset + len(data_to_write)] = data_to_write

    # Write back to the flash image file
    with open(flash_image_bin, 'wb') as f:
        f.write(flash_data)


def read_bin_from_flash_image(dut, offset, size):
    """Read binary data from flash image at specified offset using file
    operations"""
    flash_image_bin = os.path.join(dut.app.binary_path, 'flash_image.bin')
    assert os.path.exists(flash_image_bin), (
        f"Flash image not found: {flash_image_bin}"
    )

    with open(flash_image_bin, 'rb') as f:
        f.seek(offset)
        return f.read(size)


def setup_flash_image_for_qemu(dut, format='cust_flash_tlv'):

    # Search for the binaries in the qemu_test directory
    secure_cert_bin = glob.glob(
        os.path.join('qemu_test', format, f'{format}.bin'),
        recursive=True
    )[0]
    partition_table_bin = os.path.join(
        'qemu_test', format, 'partition-table.bin'
    )

    assert os.path.exists(secure_cert_bin), (
        f"No {format}.bin found in qemu_test directory"
    )
    assert os.path.exists(partition_table_bin), (
        f"TLV partition table not found: {partition_table_bin}"
    )

    try:
        # Get the existing flash_image.bin from the build directory
        flash_image_bin = os.path.join(dut.app.binary_path, 'flash_image.bin')
        assert os.path.exists(flash_image_bin), (
            f"Flash image not found: {flash_image_bin}"
        )

    except Exception as e:
        pytest.fail(f"Unexpected error: {e}")

    try:
        # Write the partition table and secure cert data to the flash image
        write_bin_to_flash_image(
            dut, partition_table_bin, PARTITION_TABLE_OFFSET
        )

        write_bin_to_flash_image(dut, secure_cert_bin, SECURE_CERT_OFFSET)

        flash_img_size = os.path.getsize(flash_image_bin)
        expected_size = 2 * 1024 * 1024  # 2MB (set in the sdkconfig)
        print(f"flash_img_size {flash_img_size}")
        print(f"expected_size {expected_size}")
        assert flash_img_size == expected_size, (
            f"Flash image size {flash_img_size} is incorrect, "
            f"expected {expected_size}"
        )

        # Read the original partition table and secure cert data from the files
        # and check that they match the original data
        with open(partition_table_bin, 'rb') as f:
            original_partition = f.read()

        with open(secure_cert_bin, 'rb') as f:
            original_secure_cert = f.read()

        partition_size = os.path.getsize(partition_table_bin)
        secure_cert_size = os.path.getsize(secure_cert_bin)

        partition_readback = read_bin_from_flash_image(
            dut, PARTITION_TABLE_OFFSET, partition_size
        )
        secure_cert_readback = read_bin_from_flash_image(
            dut, SECURE_CERT_OFFSET, secure_cert_size
        )

        # Check that the partition table and secure cert data match the
        # original data
        assert partition_readback == original_partition, (
            "Partition table data mismatch"
        )
        assert secure_cert_readback == original_secure_cert, (
            "esp_secure_cert data mismatch"
        )
    except Exception as e:
        pytest.fail(f"Unexpected error: {e}")


def verify_certificates_and_keys(dut, format='cust_flash_tlv'):
    try:
        # Get the input data from the input_data directory
        input_data_dir = os.path.join(
            'qemu_test', format, 'input_data'
        )
        if os.path.isdir(input_data_dir):
            ca_cert_file = glob.glob(
                os.path.join(input_data_dir, 'ca_cert.pem')
            )[0]
            dev_cert_file = glob.glob(
                os.path.join(input_data_dir, 'device_cert.pem')
            )[0]
            priv_key = glob.glob(
                os.path.join(input_data_dir, 'priv_key.pem')
            )[0]
        else:
            pytest.fail(f"Input data directory not found: {input_data_dir}")

        # Read the CA Cert, Device Cert, and Private Key from the input_data
        # directory
        with open(ca_cert_file, 'rb') as f:
            ca_cert_data = f.read()
        ca_cert_sha256 = hashlib.sha256(ca_cert_data).hexdigest()

        with open(dev_cert_file, 'rb') as f:
            dev_cert_data = f.read()
        dev_cert_sha256 = hashlib.sha256(dev_cert_data).hexdigest()

        with open(priv_key, 'rb') as f:
            priv_key_data = f.read()
        priv_key_sha256 = hashlib.sha256(priv_key_data).hexdigest()

        # Extract Device Cert SHA256 from the firmware log
        try:
            result = dut.expect(
                r'SHA256 of Device Cert: ([0-9a-fA-F]{64})', timeout=10
            )

            fw_device_cert_sha256 = result.group(1).decode('utf-8').lower()

            assert fw_device_cert_sha256 == dev_cert_sha256, (
                f"Device Cert SHA256 mismatch: firmware log="
                f"{fw_device_cert_sha256}, file={dev_cert_sha256}"
            )

        except Exception as e:
            pytest.fail(f"Could not extract Device Cert SHA256 from logs: {e}")

        # Extract CA Cert SHA256 from the firmware log
        try:
            result = dut.expect(
                r'SHA256 of CA Cert: ([0-9a-fA-F]{64})', timeout=10
            )
            fw_ca_cert_sha256 = result.group(1).decode('utf-8').lower()

            assert fw_ca_cert_sha256 == ca_cert_sha256, (
                f"CA Cert SHA256 mismatch: firmware log="
                f"{fw_ca_cert_sha256}, file={ca_cert_sha256}"
            )

        except Exception as e:
            pytest.fail(f"Could not extract CA Cert SHA256 from logs: {e}")

        # Extract Private Key SHA256 from the firmware log
        try:
            result = dut.expect(
                r'SHA256 of Private Key: ([0-9a-fA-F]{64})', timeout=10
            )
            fw_priv_key_sha256 = result.group(1).decode('utf-8').lower()

            assert fw_priv_key_sha256 == priv_key_sha256, (
                f"Private Key SHA256 mismatch: firmware log="
                f"{fw_priv_key_sha256}, file={priv_key_sha256}"
            )
        except Exception as e:
            pytest.fail(f"Could not extract Private Key SHA256 from logs: {e}")
    except Exception as e:
        pytest.fail(f"Unexpected error: {e}")


@pytest.mark.qemu
@pytest.mark.parametrize('config', ['legacy'], indirect=True)
@pytest.mark.parametrize('target', ['esp32c3'])
def test_esp_secure_cert_nvs_legacy_qemu(dut):
    setup_flash_image_for_qemu(dut, 'nvs_legacy')
    verify_certificates_and_keys(dut, 'nvs_legacy')
    dut.expect(r'Test application completed successfully', timeout=10)


@pytest.mark.qemu
@pytest.mark.parametrize('config', ['legacy'], indirect=True)
@pytest.mark.parametrize('target', ['esp32c3'])
def test_esp_secure_cert_cust_flash_legacy_qemu(dut):
    setup_flash_image_for_qemu(dut, 'cust_flash_legacy')
    verify_certificates_and_keys(dut, 'cust_flash_legacy')
    dut.expect(r'Test application completed successfully', timeout=10)


@pytest.mark.qemu
@pytest.mark.parametrize('config', ['legacy'], indirect=True)
@pytest.mark.parametrize('target', ['esp32c3'])
def test_esp_secure_cert_cust_flash_qemu(dut):
    setup_flash_image_for_qemu(dut, "cust_flash")
    verify_certificates_and_keys(dut, "cust_flash")
    dut.expect(r'Test application completed successfully', timeout=10)


@pytest.mark.qemu
@pytest.mark.parametrize('config', ['legacy'], indirect=True)
@pytest.mark.parametrize('target', ['esp32c3'])
def test_esp_secure_cert_nvs_qemu(dut):
    setup_flash_image_for_qemu(dut, "nvs")
    verify_certificates_and_keys(dut, "nvs")
    dut.expect(r'Test application completed successfully', timeout=10)


@pytest.mark.qemu
@pytest.mark.parametrize('config', ['tlv'], indirect=True)
@pytest.mark.parametrize('target', ['esp32', 'esp32c3', 'esp32s3'])
def test_esp_secure_cert_tlv_qemu(dut):
    setup_flash_image_for_qemu(dut)
    verify_certificates_and_keys(dut)
    dut.expect(r'Test application completed successfully', timeout=10)


@pytest.mark.parametrize('config', ['tlv'], indirect=True)
@pytest.mark.parametrize('target', ['esp32', 'esp32c3', 'esp32s3'])
def test_esp_secure_cert_tlv(dut):
    verify_certificates_and_keys(dut)
    dut.expect(r'Test application completed successfully', timeout=10)
