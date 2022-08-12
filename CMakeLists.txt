set(srcs "srcs/esp_secure_cert_tlv_read.c")

if(CONFIG_ESP_SECURE_CERT_SUPPORT_LEGACY_FORMAT)
    list(APPEND srcs "srcs/esp_secure_cert_read.c")
endif()

idf_component_register(SRCS ${srcs}
                    INCLUDE_DIRS "include"
                    PRIV_INCLUDE_DIRS "private_include"
                    REQUIRES spi_flash mbedtls nvs_flash)
