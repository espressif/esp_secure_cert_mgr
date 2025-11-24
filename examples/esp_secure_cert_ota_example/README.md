# ESP Secure Cert OTA Example

This example demonstrates how to perform OTA (Over-The-Air) updates on the `esp_secure_cert` partition in ESP-IDF. The example shows three different OTA strategies:

1. **Use Unallocated Space** - Find unallocated flash space for staging
2. **Use Passive OTA Partition** - Use the passive OTA app partition for staging
3. **Direct OTA** - Update directly without staging (risky)

## Overview

The `esp_secure_cert` partition stores device certificates and private keys. Updating this partition requires careful handling to prevent bricking the device. This example demonstrates three different approaches with varying levels of safety and resource requirements.

## Requirements

* ESP-IDF v5.0 or higher
* ESP32 series chip (ESP32, ESP32-C3, ESP32-S2, ESP32-S3, etc.)
* Pre-provisioned `esp_secure_cert` partition

## OTA Modes

### 1. Use Unallocated Space (Recommended)

**Config:** `CONFIG_EXAMPLE_ESP_SECURE_CERT_OTA_USE_UNALLOCATED_SPACE`

This mode finds unallocated space in flash and uses it as a staging area.

**How it works:**
- Scans flash partition table to find gaps between partitions
- Uses unallocated space as staging area for download
- Saves staging offset in NVS before download starts
- If interrupted, can resume on next boot
- After successful download, copies staging to original partition
- Clears NVS entry after successful copy

**Advantages:**
- Safe: Original partition untouched during download
- Rollback capable: Interrupted downloads don't corrupt original
- Resume capable: Can continue interrupted downloads

**Requirements:**
- Requires unallocated flash space ≥ esp_secure_cert partition size
- NVS partition for tracking staging state

### 2. Use Passive OTA Partition

**Config:** `CONFIG_EXAMPLE_ESP_SECURE_CERT_USE_PASSIVE_OTA`

This mode uses the passive OTA app partition as staging area.

**How it works:**
- Finds the passive (non-running) OTA partition
- Validates that partition has no valid app image
- Uses it as staging area for download
- Saves staging offset in NVS before download
- After successful download, copies to original partition
- Clears NVS entry after successful copy

**Advantages:**
- Safe: Original partition untouched during download
- Rollback capable: Interrupted downloads don't corrupt original
- No additional flash space needed

**Requirements:**
- OTA partition must be large enough (typically 1MB+)
- OTA partition must not have valid app image
- NVS partition for tracking staging state
- `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y`

**Note:** If passive OTA partition has a valid image, you must either:
- Perform an app OTA first to clear it, or
- Manually erase the partition

### 3. Direct OTA (Not Recommended)

**Config:** `CONFIG_EXAMPLE_ESP_SECURE_CERT_DIRECT_OTA`

This mode writes directly to the original partition without staging.

**How it works:**
- Erases original partition
- Writes new data directly
- No staging, no NVS tracking

**Advantages:**
- Simple implementation
- No additional flash space needed
- No NVS overhead

**Disadvantages:**
- ⚠️ **DANGEROUS**: Interruption will corrupt partition
- No rollback capability
- No resume capability
- Device may become unbootable if interrupted

**Use only if:**
- You have no unallocated space
- You cannot use passive OTA partition
- You have a recovery mechanism (e.g., JTAG, factory reset)

## Project Structure

```
esp_secure_cert_ota_example/
├── CMakeLists.txt          # Root CMakeLists.txt with partition flashing logic
├── partitions.csv          # Partition table with OTA partitions
├── README.md               # This file
├── sdkconfig.defaults      # Default configuration
└── main/
    ├── CMakeLists.txt      # Main component dependencies
    ├── Kconfig.projbuild   # Configuration options
    ├── idf_component.yml   # Component dependencies
    └── app_main.c          # Main application code
```

## Partition Table

The example uses the following partition layout:

```csv
# Name,              Type,    SubType,   Offset,   Size,    Flags
esp_secure_cert,     0x3F,    ,          0xD000,   0x2000,  encrypted
factory,             app,     factory,   0x20000,  1M,
ota_0,               app,     ota_0,     0x120000, 1M,
ota_1,               app,     ota_1,     0x220000, 1M,
otadata,             data,    ota,       0x320000, 0x2000,
nvs,                 data,    nvs,       0x9000,   0x6000,
```

**Key partitions:**
- `esp_secure_cert`: Stores device certificates and keys
- `factory`, `ota_0`, `ota_1`: App partitions for OTA
- `otadata`: OTA metadata
- `nvs`: Configuration storage and staging info

## How to Use

### 1. Set Target Chip

```bash
idf.py set-target esp32c3  # or esp32, esp32s2, esp32s3, etc.
```

### 2. Configure OTA Mode

Configure the OTA mode using menuconfig:

```bash
idf.py menuconfig
```

Navigate to: `ESP Secure Cert OTA Example Configuration` → `ESP Secure Cert OTA Mode`

Select one of:
- **Use Unallocated Space** (default, recommended)
- **Use Passive OTA Partition**
- **Direct OTA** (not recommended)

Alternatively, edit `sdkconfig.defaults`:

```ini
# For unallocated space mode:
CONFIG_EXAMPLE_ESP_SECURE_CERT_OTA_USE_UNALLOCATED_SPACE=y

# For passive OTA mode:
# CONFIG_EXAMPLE_ESP_SECURE_CERT_USE_PASSIVE_OTA=y

# For direct OTA mode (not recommended):
# CONFIG_EXAMPLE_ESP_SECURE_CERT_DIRECT_OTA=y
```

### 3. Generate and Flash esp_secure_cert Partition

The `esp_secure_cert` partition must be generated and flashed:

```bash
# Generate using the provisioning tool
python ../../tools/configure_esp_secure_cert.py \
    --esp_secure_cert_csv your_config.csv \
    --port /dev/ttyUSB0 \
    --target_chip esp32c3

# Or flash manually
esptool.py --chip esp32c3 -p /dev/ttyUSB0 write_flash 0xD000 esp_secure_cert.bin
```

See the [tools README](../../tools/README.md) for details on generating the partition.

### 4. Build and Flash

Build the project and flash it:

```bash
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

### 5. Observe OTA Process

The example will automatically perform an OTA operation on boot:

**For Unallocated Space mode:**
```
I (331) esp_secure_cert_ota: === OTA Mode: Use Unallocated Space ===
I (341) esp_secure_cert_ota: Starting new OTA operation
I (351) esp_secure_cert_ota: Found unallocated space at offset 0x00330000, size: 8192 bytes
I (361) esp_secure_cert_ota: Downloading OTA data to staging area at offset 0x00330000
I (371) esp_secure_cert_ota: Successfully downloaded 8 bytes to staging area
I (381) esp_secure_cert_ota: Copying staging area to original partition
I (391) esp_secure_cert_ota: Successfully copied staging area to original partition
I (401) esp_secure_cert_ota: OTA completed successfully
```

**For Passive OTA mode:**
```
I (331) esp_secure_cert_ota: === OTA Mode: Use Passive OTA Partition ===
I (341) esp_secure_cert_ota: Running partition: factory at offset 0x00020000
I (351) esp_secure_cert_ota: Passive OTA partition: ota_0 at offset 0x00120000
I (361) esp_secure_cert_ota: Passive OTA partition ota_0 is available for staging
I (371) esp_secure_cert_ota: Starting new OTA operation
I (381) esp_secure_cert_ota: Download completed successfully
I (391) esp_secure_cert_ota: Successfully copied staging area to original partition
I (401) esp_secure_cert_ota: OTA completed successfully
```

**For Direct OTA mode:**
```
I (331) esp_secure_cert_ota: === OTA Mode: Direct OTA ===
W (341) esp_secure_cert_ota: WARNING: Direct OTA mode is risky!
W (351) esp_secure_cert_ota: WARNING: Any interruption will corrupt the esp_secure_cert partition!
I (361) esp_secure_cert_ota: Target partition: esp_secure_cert at offset 0x0000D000
I (371) esp_secure_cert_ota: Successfully wrote 8 bytes to partition
I (381) esp_secure_cert_ota: Direct OTA completed successfully
```

## Testing Interruption Recovery

### Test Unallocated Space Mode Recovery

1. Build and flash the example
2. During download, reset the device (unplug power)
3. Power on again
4. The example will detect incomplete staging and resume:

```
I (331) esp_secure_cert_ota: Found incomplete staging operation, resuming...
I (341) esp_secure_cert_ota: Successfully completed pending OTA
```

### Test Passive OTA Mode Recovery

Same as unallocated space mode - the NVS entry persists across reboots.

## Configuration Options

### Kconfig Options

| Option | Description | Default |
|--------|-------------|---------|
| `CONFIG_EXAMPLE_ESP_SECURE_CERT_OTA_USE_UNALLOCATED_SPACE` | Use unallocated space mode | Yes |
| `CONFIG_EXAMPLE_ESP_SECURE_CERT_USE_PASSIVE_OTA` | Use passive OTA partition mode | No |
| `CONFIG_EXAMPLE_ESP_SECURE_CERT_DIRECT_OTA` | Use direct OTA mode | No |
| `CONFIG_EXAMPLE_OTA_RECV_TIMEOUT` | OTA receive timeout (ms) | 5000 |

### Partition Table Customization

If you need to customize partition sizes, edit `partitions.csv`:

```csv
# Name,              Type,    SubType,   Offset,   Size,    Flags
esp_secure_cert,     0x3F,    ,          0xD000,   0x2000,  encrypted
factory,             app,     factory,   0x20000,  1M,
ota_0,               app,     ota_0,     0x120000, 1M,
ota_1,               app,     ota_1,     0x220000, 1M,
otadata,             data,    ota,       0x320000, 0x2000,
nvs,                 data,    nvs,       0x9000,   0x6000,
```

**Important considerations:**
- `esp_secure_cert` size must match your certificate data size
- OTA app partitions must be large enough for your application
- Ensure sufficient unallocated space for staging (if using that mode)

## API Usage

The example demonstrates usage of ESP-IDF APIs:

### Partition APIs
```c
esp_partition_find_first()
esp_partition_erase_range()
esp_partition_write()
esp_partition_read()
```

### OTA APIs
```c
esp_ota_get_running_partition()
esp_ota_get_next_update_target()
esp_ota_get_partition_description()
```

### Flash APIs
```c
esp_flash_get_size()
esp_flash_read()
esp_flash_write()
esp_flash_erase_region()
```

### NVS APIs
```c
nvs_open()
nvs_set_u32()
nvs_get_u32()
nvs_commit()
nvs_close()
```

## Real-World Integration

This example uses simulated OTA data. In a real application, integrate with download code:

```c
static esp_err_t download_to_staging(uint32_t staging_offset, size_t staging_size)
{
    // 1. Initialize HTTP/HTTPS client
    esp_http_client_config_t config = {
        .url = "https://your-server.com/cert.bin",
        // Add certificate authentication if needed
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    
    // 2. Erase staging area
    esp_flash_erase_region(NULL, staging_offset, staging_size);
    
    // 3. Download and write in chunks
    uint8_t buffer[4096];
    size_t offset = 0;
    while (offset < staging_size) {
        int read_len = esp_http_client_read(client, buffer, sizeof(buffer));
        if (read_len <= 0) break;
        
        esp_flash_write(NULL, buffer, staging_offset + offset, read_len);
        offset += read_len;
    }
    
    // 4. Cleanup
    esp_http_client_cleanup(client);
    return ESP_OK;
}
```

## Troubleshooting

### "No unallocated space found"

**Problem:** Not enough unallocated flash space for staging.

**Solutions:**
1. Use passive OTA partition mode instead
2. Reduce size of other partitions
3. Use larger flash chip
4. Use direct OTA mode (not recommended)

### "Passive OTA partition has valid image"

**Problem:** Passive OTA partition contains a valid app image.

**Solutions:**
1. Perform an app OTA update to swap partitions
2. Manually erase the passive partition:
   ```bash
   esptool.py --chip esp32c3 -p /dev/ttyUSB0 erase_region 0x120000 0x100000
   ```
3. Use unallocated space mode instead

### "Failed to save staging info"

**Problem:** NVS partition not initialized or corrupted.

**Solutions:**
1. Ensure NVS is initialized: `nvs_flash_init()`
2. Erase and reinitialize NVS:
   ```bash
   esptool.py --chip esp32c3 -p /dev/ttyUSB0 erase_region 0x9000 0x6000
   ```

### Device won't boot after Direct OTA

**Problem:** Direct OTA was interrupted, corrupting the partition.

**Solutions:**
1. Reflash the esp_secure_cert partition:
   ```bash
   esptool.py --chip esp32c3 -p /dev/ttyUSB0 write_flash 0xD000 esp_secure_cert.bin
   ```
2. Use factory reset if available
3. Use JTAG debugger to recover

## Best Practices

1. **Always prefer staged OTA** (unallocated or passive OTA modes)
2. **Test interruption recovery** before production deployment
3. **Validate downloaded data** before copying to original partition
4. **Monitor battery level** on battery-powered devices
5. **Implement retry logic** for download failures
6. **Log all operations** for debugging
7. **Test on multiple devices** before mass deployment

## Security Considerations

1. **Use HTTPS** for downloading OTA data
2. **Verify signatures** of downloaded data before flashing
3. **Enable flash encryption** for sensitive partitions
4. **Protect NVS data** with encryption if needed
5. **Implement authentication** for OTA server access
6. **Use secure boot** to prevent unauthorized firmware

## Performance

### Memory Usage
- Stack: ~8KB
- Heap: ~8KB (for copy buffer)
- NVS: ~16 bytes per OTA operation

### Flash Wear
- Each OTA operation: 2-3 erase cycles on affected sectors
- Staged modes: Extra wear on staging area
- Use wear leveling if doing frequent OTA updates

### Timing
- Unallocated space mode: 5-30 seconds (depends on size)
- Passive OTA mode: 5-30 seconds (depends on size)
- Direct OTA mode: 3-10 seconds (depends on size)

## Additional Resources

- [ESP Secure Cert Manager Documentation](../../README.md)
- [ESP-IDF OTA Documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/system/ota.html)
- [ESP-IDF Partition API](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/spi_flash.html)
- [ESP-IDF NVS Documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/nvs_flash.html)

## License

This example is provided under the Apache License 2.0. See LICENSE file for details.

## Contributing

Contributions are welcome! Please follow the ESP-IDF contribution guidelines.
