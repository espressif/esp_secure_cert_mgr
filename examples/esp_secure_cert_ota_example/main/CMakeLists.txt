idf_build_get_property(project_dir PROJECT_DIR)
idf_component_register(
    SRC_DIRS "."
    INCLUDE_DIRS "."
    REQUIRES esp_secure_cert_mgr app_update nvs_flash esp_partition spi_flash bootloader_support
             esp_https_ota esp_http_client esp_wifi esp_netif esp_event protocol_examples_common
    EMBED_TXTFILES ${project_dir}/certs/ca_cert.pem ${project_dir}/certs/ca_key.pem
    )
