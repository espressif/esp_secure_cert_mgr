# Test configuration and shared fixtures for test_apps
import pytest
import os

@pytest.fixture(scope="session")
def test_data_path():
    """Fixture to provide the path to test data"""
    return os.path.join(os.path.dirname(__file__), '..', 'qemu_test')
