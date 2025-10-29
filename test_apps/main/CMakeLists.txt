# SPDX-FileCopyrightText: 2022-2025 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

# Main component for ESP Secure Cert Test Application
# This component contains Unity-based tests for esp_secure_cert_mgr

# Check IDF version for WHOLE_ARCHIVE support (available from IDF 5.0)
if(IDF_VERSION_MAJOR GREATER_EQUAL 5)
    idf_component_register(
        SRC_DIRS "." "crypto" "tlv_legacy"
        INCLUDE_DIRS "." "../../private_include"
        REQUIRES unity
        WHOLE_ARCHIVE
    )
else()
    # For IDF 4.x, register without WHOLE_ARCHIVE
    idf_component_register(
        SRC_DIRS "." "crypto" "tlv_legacy"
        INCLUDE_DIRS "." "../../private_include"
        REQUIRES unity
    )
endif()
