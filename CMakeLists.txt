set(srcs "srcs/esp_secure_cert_tlv_read.c" "srcs/esp_secure_cert_crypto.c")

if(CONFIG_ESP_SECURE_CERT_SUPPORT_LEGACY_FORMATS)
    list(APPEND srcs "srcs/esp_secure_cert_read.c")
endif()

set(reqs "")
# Check IDF version - esp_partition is a separate component only in IDF v5.0+
# In v4.3, esp_partition APIs are part of spi_flash component
idf_build_get_property(idf_version IDF_VERSION)
if(idf_version VERSION_GREATER_EQUAL "5.0")
    idf_build_get_property(build_components BUILD_COMPONENTS)
    if(esp_partition IN_LIST build_components)
        list(APPEND reqs esp_partition)
    endif()
endif()

if(CONFIG_ESP_SECURE_CERT_SECURE_VERIFICATION)
    if(IDF_VERSION_MAJOR LESS 5 OR (IDF_VERSION_MAJOR EQUAL 5 AND IDF_VERSION_MINOR LESS 3))
        message(FATAL_ERROR
            "\n"
            "===============================================================================\n"
            "ERROR: ESP_SECURE_CERT_SECURE_VERIFICATION is not supported for ESP-IDF version ${idf_version}\n"
            "===============================================================================\n"
            "The secure verification feature requires ESP-IDF version >= 5.3.\n"
            "Current ESP-IDF version: ${idf_version}\n"
            "Please either:\n"
            "  1. Upgrade to ESP-IDF >= 5.3, or\n"
            "  2. Disable CONFIG_ESP_SECURE_CERT_SECURE_VERIFICATION in your sdkconfig\n"
            "===============================================================================\n"
        )
    endif()
    list(APPEND srcs "srcs/esp_secure_cert_signature_verify.c")
endif()

idf_component_register(SRCS ${srcs}
                    INCLUDE_DIRS "include"
                    PRIV_INCLUDE_DIRS "private_include"
                    PRIV_REQUIRES nvs_flash efuse bootloader_support
                    REQUIRES ${reqs} spi_flash mbedtls)
