#include <string.h>
#include <inttypes.h>
#include "esp_log.h"
#include "esp_secure_cert_read.h"
#include "esp_secure_cert_tlv_read.h"
#if (MBEDTLS_MAJOR_VERSION < 4)
#include "mbedtls/sha256.h"
#else
#include "psa/crypto.h"
#endif


#define TAG "test_esp_secure_cert_tlv"

#if (MBEDTLS_MAJOR_VERSION < 4)
static esp_err_t get_sha256(const char *data, uint32_t len, unsigned char *sha256)
{
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, (const unsigned char *)data, len);
    mbedtls_sha256_finish(&sha_ctx, sha256);
    mbedtls_sha256_free(&sha_ctx);
    return ESP_OK;
}
#else
static esp_err_t get_sha256(const char *data, uint32_t len, uint8_t *sha256)
{
    size_t hash_len = 0;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, (const uint8_t *)data, len, sha256, 32, &hash_len);
    if (status != PSA_SUCCESS) {
        return ESP_FAIL;
    }
    return ESP_OK;
}
#endif

static void print_sha256_of_data(const char *label, const char *data, uint32_t len)
{
    if (len > 0 && data != NULL) {
        char sha256_str[65] = {0};
        uint8_t sha256[32] = {0};
        get_sha256(data, len, sha256);
        for (int i = 0; i < 32; i++) {
            snprintf(&sha256_str[i * 2], 3, "%02X", sha256[i]);
        }
        ESP_LOGI(TAG, "SHA256 of %s: %s", label, sha256_str);
    } else {
        ESP_LOGW(TAG, "%s: No data found for sha256 calculation", label);
    }
}


// Function to print certificate or key data in PEM or DER format
static void esp_print_cert_or_key(const char *label, const char *data, uint32_t len)
{
    if (len > 0 && data != NULL) {
        const char *pem_header = "-----BEGIN";
        if (strncmp(data, pem_header, strlen(pem_header)) == 0) {
            ESP_LOGI(TAG, "%s (PEM): \nLength: %"PRIu32"\n%s", label, len, data);
        } else {
            ESP_LOGI(TAG, "%s (DER): \nLength: %"PRIu32"\n", label, len);
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, data, len, ESP_LOG_INFO);
        }
        // Optimize: handle PEM (null-terminated) and DER (binary) length for SHA256 calculation
        size_t actual_len = len;
        if (strncmp(data, pem_header, strlen(pem_header)) == 0) {
            actual_len -= 1; // Remove the last '\0' from the PEM data for sha256 calculation
        }
        print_sha256_of_data(label, data, actual_len);
    } else {
        ESP_LOGW(TAG, "%s: No data found", label);
    }
}

void esp_secure_cert_tlv_test()
{
    esp_err_t esp_ret = ESP_FAIL;

    ESP_LOGI(TAG, "Starting ESP Secure Cert TLV Test Application");

    // Read Device Certificate using TLV format
    // Use the standard API to get device and CA certs, as in esp_secure_cert_get_device_cert and esp_secure_cert_get_ca_cert
    uint32_t len = 0;
    char *addr = NULL;

    // Read Device Certificate using standard API
    esp_ret = esp_secure_cert_get_device_cert(&addr, &len);
    if (esp_ret == ESP_OK) {
        esp_print_cert_or_key("Device Cert", (const char *)addr, len);
    } else {
        ESP_LOGE(TAG, "Failed to obtain flash address of device cert");
    }

    // Read CA Certificate using standard API
    esp_ret = esp_secure_cert_get_ca_cert(&addr, &len);
    if (esp_ret == ESP_OK) {
        esp_print_cert_or_key("CA Cert", (const char *)addr, len);
    } else {
        ESP_LOGE(TAG, "Failed to obtain flash address of ca_cert");
    }

#ifndef CONFIG_ESP_SECURE_CERT_DS_PERIPHERAL
    // Read Private Key using standard format (for comparison)
    uint32_t priv_key_len = 0;
    char *priv_key_addr = NULL;
    esp_ret = esp_secure_cert_get_priv_key(&priv_key_addr, &priv_key_len);
    if (esp_ret == ESP_OK) {
        esp_print_cert_or_key("Private Key", (const char *)priv_key_addr, priv_key_len);
    } else {
        ESP_LOGE(TAG, "Failed to read Private Key using standard format: %s", esp_err_to_name(esp_ret));
    }
#endif
#ifndef CONFIG_ESP_SECURE_CERT_SUPPORT_LEGACY_FORMATS
    // List all TLV entries
    ESP_LOGI(TAG, "Listing all TLV entries:");
    esp_secure_cert_list_tlv_entries();
#endif

    if (esp_ret == ESP_OK) {
        ESP_LOGI(TAG, "Test application completed successfully");
    } else {
        ESP_LOGE(TAG, "Test application failed");
    }
}
