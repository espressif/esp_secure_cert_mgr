# Main component for ESP Secure Cert TLV Test Application

# Define component dependencies
set(component_requires
    mbedtls
    spi_flash
    nvs_flash
    efuse
)

set(srcs "app_main.c" 
        "../../srcs/esp_secure_cert_tlv_read.c" 
        "../../srcs/esp_secure_cert_crypto.c" 
        "../../srcs/esp_secure_cert_read.c")

# Register the component
idf_component_register(
    SRC_DIRS "."
    INCLUDE_DIRS "."
    REQUIRES ${component_requires}
    PRIV_INCLUDE_DIRS "../../include" "../../private_include"
    SRCS ${srcs}
)
