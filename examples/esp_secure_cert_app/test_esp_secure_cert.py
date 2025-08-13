import pytest

@pytest.mark.qemu
@pytest.mark.parametrize('target', ['esp32c3'], indirect=True)
def test_esp_secure_cert_sanity(dut):
    """Simple sanity check to verify the application is working"""
    # Check if the application starts successfully
    dut.expect(r'Returned from app_main()', timeout=10)
