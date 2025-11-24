idf_component_register(
    SRC_DIRS "."
    INCLUDE_DIRS "."
    REQUIRES esp_secure_cert_mgr app_update nvs_flash esp_partition spi_flash bootloader_support
             esp_https_ota esp_http_client esp_wifi esp_netif esp_event protocol_examples_common
    )

# Embed the server root certificate into the final binary (only if using HTTPS without cert bundle)
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../server_certs/ca_cert.pem")
    target_add_binary_data(${COMPONENT_LIB} "../server_certs/ca_cert.pem" TEXT)
endif()
