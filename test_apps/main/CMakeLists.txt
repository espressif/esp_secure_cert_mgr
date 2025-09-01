# Check IDF version for WHOLE_ARCHIVE support (available from IDF 5.0)
if(IDF_VERSION_MAJOR GREATER_EQUAL 5)
    idf_component_register(
        SRC_DIRS "." "crypto" "tlv_legacy" "basics" "secure_verification"
        INCLUDE_DIRS "." "../../private_include"
        REQUIRES unity mbedtls efuse bootloader
        WHOLE_ARCHIVE
    )
else()
    # For IDF 4.x, register without WHOLE_ARCHIVE
    idf_component_register(
        SRC_DIRS "." "crypto" "tlv_legacy" "basics" "secure_verification"
        INCLUDE_DIRS "." "../../private_include"
        REQUIRES unity mbedtls efuse bootloader
    )
endif()
