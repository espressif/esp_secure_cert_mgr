# ESP Secure Certificate Signature Verification

This document explains the signature verification functionality in the ESP Secure Certificate component, including secure verification integration, signature block format, and how to configure and test signature verification.

## 1. Adding signature block in esp_secure_cert partition

### Signature block

Signature block is calculated using the sha of all the TLV entries except `ESP_SECURE_CERT_SIGNATURE_BLOCK_TLV` and signing_key. For the creation of signature block `generate_signature_block_using_private_key` from `esptool.py`. And appended in the end of esp_secure_cert partition as TLV entry.

#### Signing key

User need to generate the signing_keys on host, and ensure that same keys are used for the secure boot or keys digest is stored in the efuse for verification. User can generate three signature blocks for corresponding three signing keys with same signing scheme.

#### Signature Block format

The signature blocks are stored in TLV (Type-Length-Value) format within the esp_secure_cert partition. Each signature block contains:

### TLV Header Structure
```c
typedef struct {
    uint32_t magic;        // Magic number: 0xBA5EBA11
    uint8_t type;          // TLV type: ESP_SECURE_CERT_SIGNATURE_BLOCK_TLV (7)
    uint8_t subtype;       // Subtype identifier (0, 1, 2, etc.)
    uint16_t length;       // Length of signature block data
} esp_secure_cert_tlv_header_t;
```

### Signature Block Data
The signature block data follows the ESP-IDF secure boot v2 format:

```c
typedef struct {
    uint8_t signature[384];  // RSA-3072 signature (384 bytes)
    uint8_t key[544];        // RSA-3072 public key (544 bytes)
    // Additional metadata may be present
} esp_secure_cert_sig_block_t;
```

### TLV Footer
```c
typedef struct {
    uint32_t crc;          // CRC32 of header + data + padding
} esp_secure_cert_tlv_footer_t;
```

### Multiple Signature Blocks
The system supports up to 3 signature blocks for redundancy:
- **Signature Block 0**: Primary signature block
- **Signature Block 1**: Secondary signature block  
- **Signature Block 2**: Tertiary signature block

The verification process tries each signature block in order until one succeeds.

**NOTE - Signature Block order will be not decided on the subtype basis, but with signing key order passed as parameter in configure_esp_secure_cert.py tool**

#### Block Diagram

![](../_static/signature_block.png)

- SHA is calculated from all TLV entries except SIGNATURE_BLOCK_TLV.
- Signature Block TLV is created with generated signature block using SHA and signing key.
- Signature Block TLV will be appended at the end of all entries.

## 2. Secure Boot Verification

The ESP Secure Certificate component provides built-in signature verification functionality that integrates with ESP-IDF's secure boot system. The signature verification is performed at application startup to ensure the integrity and authenticity of the esp_secure_cert partition.

### API Usage

The signature verification is automatically called in the application's `app_main()` function when the `CONFIG_ESP_SECURE_CERT_SECURE_VERIFICATION` configuration is enabled:

```c
#include "esp_secure_cert_signature_verify.h"

void app_main()
{
#if CONFIG_ESP_SECURE_CERT_SECURE_VERIFICATION
    // Perform signature verification at startup
    ESP_LOGI(TAG, "Starting esp_secure_cert partition signature verification...");
    esp_err_t sig_ret = esp_secure_cert_verify_partition_signature();
    if (sig_ret == ESP_OK) {
        ESP_LOGI(TAG, "✅ esp_secure_cert partition signature verification PASSED");
    } else {
        ESP_LOGE(TAG, "❌ esp_secure_cert partition signature verification FAILED");
    }
#endif
    
    // Continue with normal application logic...
}
```

The verification process:
1. Calculates a SHA256 hash of all TLV entries except signature blocks
2. Verifies the signature using the embedded public key in the signature block
3. Supports multiple signature blocks for redundancy
4. Returns `ESP_OK` if any signature block verification succeeds

## 3. Using configure_esp_secure_cert.py

The `configure_esp_secure_cert.py` script provides functionality to add signature blocks to existing binary files or create new signed binary files.

### Adding Signature Block to Existing Binary

To add a signature block to an existing esp_secure_cert binary file:

```bash
python tools/configure_esp_secure_cert.py \
    --bin-filename path/to/existing/esp_secure_cert.bin \
    --secure_sign \
    --signing-key-file path/to/signing_private_key.pem \
    --signing_scheme ['rsa3072', 'ecdsa192', 'ecdsa256', 'ecdsa384'] \
```

### Creating New Signed Binary

To create a new esp_secure_cert binary with signature blocks:

```bash
python tools/configure_esp_secure_cert.py \
    --private-key path/to/client_private_key.pem \
    --device-cert path/to/device_cert.pem \
    --ca-cert path/to/ca_cert.pem \
    --secure_sign
    --signing-key-file path/to/signing_private_key.pem \
    --signing_scheme ['rsa3072', 'ecdsa192', 'ecdsa256', 'ecdsa384]
    --target_chip esp32c3
```

### Command Line Options

| Option | Description | Required |
|--------|-------------|----------|
| `--bin-filename` | Path to existing binary file | For existing binaries |
| `--signing-key-file` | Path to signing private key (PEM format) | Yes |
| `--secure_sign` | To enable the signature block feature | Yes |


### Output Files

The script generates the following files in the `esp_secure_cert_data/` directory:
- `esp_secure_cert_singed_partition.bin`: Final signed binary file
- `signature_block_0.bin`: Primary signature block
- `signature_block_1.bin`: Secondary signature block (if multiple keys provided)
- `signature_block_2.bin`: Tertiary signature block (if multiple keys provided)

## 4. Configuration Requirements

### Enable Secure Boot Verification

To use signature verification, enable the following configuration in your project:

```bash
# Enable secure boot verification
idf.py menuconfig
```

Navigate to: `Component config` → `ESP Secure Certificate` → `Enable secure boot verification`

Or add to your `sdkconfig.defaults`:
```
CONFIG_ESP_SECURE_CERT_SECURE_VERIFICATION=y
```

### Partition Configuration

The esp_secure_cert partition will be automatically flashed when you build and flash your application:

```bash
idf.py build flash
```

The partition table should include:
```
# Name,   Type, SubType, Offset,  Size, Flags
nvs,      data, nvs,     0x9000,  0x6000,
phy_init, data, phy,     0xf000,  0x1000,
factory,  app,  factory, 0x10000, 1M,
esp_secure_cert, data, 0x3f, 0x20000, 0x10000,
```

## 5. Testing with QEMU

For testing signature verification functionality, it's recommended to use QEMU to avoid potential issues with real hardware during development.

### Setting Up QEMU Testing

To use signature verification, enable the following configuration in your project:

```bash
# Enable secure boot verification
idf.py menuconfig
```

Navigate to: `Component config` → `ESP Secure Certificate` → `Enable secure boot verification`

Or add to your `sdkconfig.defaults`:
```
CONFIG_ESP_SECURE_CERT_SECURE_VERIFICATION=y
```

Then run qemu, the firmware will be built automatically.

```bash
# Enable secure boot verification
idf.py qemu
```