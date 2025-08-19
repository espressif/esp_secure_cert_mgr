/*
 * SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ESP Secure Cert TLV Test Application

   This test application is designed to test the TLV format support
   of esp_secure_cert_mgr component. It only outputs TLV contents
   without complex validation logic.
*/

#include <string.h>
#include <inttypes.h>
#include "esp_log.h"
#include "esp_secure_cert_read.h"
#include "esp_secure_cert_tlv_read.h"
#include "mbedtls/sha256.h"

#define TAG "test_esp_secure_cert_tlv"

// Function to print certificate or key data in PEM or DER format
static void esp_print_cert_or_key(const char *label, const char *data, uint32_t len)
{
    if (len > 0 && data != NULL) {
        const char *pem_header = "-----BEGIN";
        if (strncmp(data, pem_header, strlen(pem_header)) == 0) {
            ESP_LOGI(TAG, "%s (PEM): \nLength: %"PRIu32"\n%s", label, len, data);
            len -= 1; // Remove the last '\0' from the PEM data for sha256 calculation
        } else {
            ESP_LOGI(TAG, "%s (DER): \nLength: %"PRIu32"\n", label, len);
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, data, len, ESP_LOG_INFO);
        }
    
        unsigned char sha256[32] = {0};
        mbedtls_sha256_context sha_ctx;
        mbedtls_sha256_init(&sha_ctx);
        mbedtls_sha256_starts(&sha_ctx, 0);
        mbedtls_sha256_update(&sha_ctx, (const unsigned char *)data, len);
        mbedtls_sha256_finish(&sha_ctx, sha256);
        mbedtls_sha256_free(&sha_ctx);

        char sha256_str[65] = {0};
        for (int i = 0; i < 32; ++i) {
            sprintf(sha256_str + i * 2, "%02x", sha256[i]);
        }

        ESP_LOGI(TAG, "SHA256 of %s: %s", label, sha256_str);
    } else {
        ESP_LOGW(TAG, "%s: No data found", label);
    }
}

void app_main()
{
    esp_err_t esp_ret = ESP_FAIL;

    ESP_LOGI(TAG, "Starting ESP Secure Cert TLV Test Application");

    // Test TLV format reading
    esp_secure_cert_tlv_config_t tlv_config = {};
    esp_secure_cert_tlv_info_t tlv_info = {};

    // Read Device Certificate using TLV format
    tlv_config.type = ESP_SECURE_CERT_DEV_CERT_TLV;
    tlv_config.subtype = ESP_SECURE_CERT_SUBTYPE_0;
    esp_ret = esp_secure_cert_get_tlv_info(&tlv_config, &tlv_info);
    if (esp_ret == ESP_OK) {
        esp_print_cert_or_key("Device Cert (TLV)", (const char *)tlv_info.data, tlv_info.length);
    } else {
        ESP_LOGE(TAG, "Failed to read Device Cert using TLV format: %s", esp_err_to_name(esp_ret));
    }

    // Read CA Certificate using TLV format
    tlv_config.type = ESP_SECURE_CERT_CA_CERT_TLV;
    tlv_config.subtype = ESP_SECURE_CERT_SUBTYPE_0;
    esp_ret = esp_secure_cert_get_tlv_info(&tlv_config, &tlv_info);
    if (esp_ret == ESP_OK) {
        esp_print_cert_or_key("CA Cert (TLV)", (const char *)tlv_info.data, tlv_info.length);
    } else {
        ESP_LOGE(TAG, "Failed to read CA Cert using TLV format: %s", esp_err_to_name(esp_ret));
    }

    // Read Private Key using TLV format
    tlv_config.type = ESP_SECURE_CERT_PRIV_KEY_TLV;
    tlv_config.subtype = ESP_SECURE_CERT_SUBTYPE_0;
    esp_ret = esp_secure_cert_get_tlv_info(&tlv_config, &tlv_info);
    if (esp_ret == ESP_OK) {
        esp_print_cert_or_key("Private Key (TLV)", (const char *)tlv_info.data, tlv_info.length);
    } else {
        ESP_LOGE(TAG, "Failed to read Private Key using TLV format: %s", esp_err_to_name(esp_ret));
    }

    // List all TLV entries
    ESP_LOGI(TAG, "Listing all TLV entries:");
    esp_secure_cert_list_tlv_entries();
    if (esp_ret == ESP_OK) {
        ESP_LOGI(TAG, "Test application completed successfully");
    } else {
        ESP_LOGE(TAG, "Test application failed");
    }
    ESP_LOGI(TAG, "Returned from app_main()");   
}
