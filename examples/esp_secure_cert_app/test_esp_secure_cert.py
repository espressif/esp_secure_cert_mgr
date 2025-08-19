import pytest

@pytest.mark.qemu
@pytest.mark.parametrize('target', ['esp32c3'], indirect=True)
def test_esp_secure_cert_sanity(dut):
    """Simple sanity check to verify the application is working"""
    # Check if the application starts successfully
    dut.expect(r'Failed to obtain the ds context', timeout=30)
    dut.expect(r'Failed to obtain the dev cert flash address', timeout=5)
    dut.expect(r'Failed to validate ciphertext', timeout=5)
    dut.expect(r'Failed to obtain and verify the contents of the esp_secure_cert partition', timeout=5)
    dut.expect(r'The esp_secure_cert partition does not appear to be valid', timeout=5)
