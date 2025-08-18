# ESP Secure Cert Manager Test Applications

This directory contains **test applications** specifically designed for testing the `esp_secure_cert_mgr` component. These applications are **NOT for production use** - they are intended solely for **testing and validation purposes**.

## Purpose

The test applications in this directory serve to:

- **Test TLV format support** of the `esp_secure_cert_mgr` component
- **Test legacy format support** (cust_flash, nvs) 
- **Validate component functionality** through automated testing
- **Provide test infrastructure** for CI/CD pipelines
- **Enable QEMU-based testing** for different flash formats

## Directory Structure

```
test_apps/
├── main/                           # Main test application source
│   ├── app_main.c                  # Test application entry point
│   └── CMakeLists.txt             # Component build configuration
├── qemu_test/                      # QEMU testing infrastructure
│   ├── cust_flash_tlv/            # TLV format test data
│   │   ├── cust_flash_tlv.bin     # Pre-built TLV flash image
│   │   ├── partition-table.bin    # Custom partition table
│   │   └── input_data/            # Source certificates and keys
│   ├── cust_flash/                # Legacy cust_flash format test data
│   ├── nvs/                       # Legacy NVS format test data
│   └── nvs_legacy/                # Legacy NVS format test data
├── test_esp_secure_cert.py        # Test script
├── sdkconfig.ci.tlv                  # TLV format configuration
├── sdkconfig.ci.legacy               # Legacy format configuration
├── sdkconfig.defaults             # Default configuration
├── partitions.csv                  # Custom partition table
├── CMakeLists.txt                 # Project build configuration
└── README.md                      # This file
```

## Test Applications

### 1. **TLV Format Test Application**
- **Purpose**: Test the modern TLV (Type-Length-Value) format support
- **Configuration**: `sdkconfig.ci.tlv`
- **Test Script**: `test_esp_secure_cert.py`
- **Features**: 
  - TLV format reading and parsing
  - Certificate and key extraction
  - TLV entry listing and validation

### 2. **Legacy Format Test Applications**
- **Purpose**: Test backward compatibility with legacy formats
- **Configurations**: `sdkconfig.ci.legacy`
- **Test Scripts**: `test_esp_secure_cert.py`
- **Features**:
  - Legacy cust_flash format support
  - Legacy NVS format support
  - Format detection and compatibility

**Note**: This directory is part of the component's testing infrastructure and should not be used as a reference for production applications. For production examples, see the `/examples/` directory.
