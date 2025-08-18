# ESP Secure Cert TLV Test Application Configuration
CONFIG_ESP_TASK_WDT_EN=n

# Partition table configuration (matching esp_secure_cert_app)
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_OFFSET=0xc000
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"

# Flash size configuration for QEMU testing
CONFIG_ESPTOOLPY_FLASHSIZE_2MB=y
CONFIG_ESPTOOLPY_FLASHSIZE="2MB"

# Logging configuration
CONFIG_LOG_DEFAULT_LEVEL_INFO=y
CONFIG_LOG_MAXIMUM_LEVEL=3
