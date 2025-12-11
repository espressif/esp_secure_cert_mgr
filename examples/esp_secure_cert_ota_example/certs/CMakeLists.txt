# Embed certificate files as binary data
idf_build_get_property(component_dir COMPONENT_DIR)

if(EXISTS "${component_dir}/../certs/ca_cert.pem")
    target_add_binary_data(${COMPONENT_LIB} "../certs/ca_cert.pem" TEXT)
endif()

if(EXISTS "${component_dir}/../certs/ca_key.pem")
    target_add_binary_data(${COMPONENT_LIB} "../certs/ca_key.pem" TEXT)
endif()
