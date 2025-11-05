# Check IDF version for WHOLE_ARCHIVE support (available from IDF 5.0)
if(IDF_VERSION_MAJOR GREATER_EQUAL 5)
    idf_component_register(
        SRC_DIRS "." "crypto" "tlv_legacy" "basics"
        INCLUDE_DIRS "." "../../private_include"
        REQUIRES unity mbedtls
        WHOLE_ARCHIVE
    )
else()
    # For IDF 4.x, register without WHOLE_ARCHIVE
    idf_component_register(
        SRC_DIRS "." "crypto" "tlv_legacy" "basics"
        INCLUDE_DIRS "." "../../private_include"
        REQUIRES unity mbedtls
    )
endif()
