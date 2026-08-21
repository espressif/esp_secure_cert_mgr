set(srcs "app_main.c")

if(CONFIG_MBEDTLS_PSA_ITS_CUSTOM_STORAGE_BACKEND AND CONFIG_ESP_SECURE_CERT_DS_PERIPHERAL)
    list(APPEND srcs "secure_cert_its_backend.c")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "."
    PRIV_REQUIRES esp_partition bootloader_support mbedtls
    )
