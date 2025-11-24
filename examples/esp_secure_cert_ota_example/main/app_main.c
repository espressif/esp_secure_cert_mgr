#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_check.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "protocol_examples_common.h"
#include "string.h"
#ifdef CONFIG_EXAMPLE_USE_CERT_BUNDLE
#include "esp_crt_bundle.h"
#endif
#include "esp_flash.h"
#include "esp_flash_partitions.h"
#include "esp_partition.h"
#include "soc/soc_caps.h"
#if SOC_RECOVERY_BOOTLOADER_SUPPORTED
#include "esp_efuse.h"
#endif
#include "nvs.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"
#include <sys/socket.h>
#if CONFIG_EXAMPLE_CONNECT_WIFI
#include "esp_wifi.h"
#endif

#include "partition_utils.h"
#include "esp_secure_cert_tlv_config.h"
#include "esp_secure_cert_read.h"
#include "esp_secure_cert_tlv_read.h"
#include "esp_partition.h"

#define ESP_SECURE_CERT_TLV_PARTITION_NAME      "esp_secure_cert"
#define ESP_SECURE_CERT_CUST_FLASH_PARTITION_TYPE           0x3F

static char TAG[] = "esp_secure_cert_ota_example";

#if defined(CONFIG_EXAMPLE_CERT_OTA_URL_USE_HTTPS) && !defined(CONFIG_EXAMPLE_USE_CERT_BUNDLE)
extern const uint8_t server_cert_pem_start[] asm("_binary_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_ca_cert_pem_end");
#endif

static void get_ca_cert()
{
    char *ca_cert_buffer = NULL;
    uint32_t ca_cert_len = 0;
    esp_err_t err = esp_secure_cert_get_ca_cert(&ca_cert_buffer, &ca_cert_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read CA certificate (err=0x%x)", err);
    } else {
        ESP_LOGI(TAG, "Successfully read CA certificate (length=%lu)", ca_cert_len);
        ESP_LOGI(TAG, "CA Certificate:\n%.*s", ca_cert_len, ca_cert_buffer);
        esp_secure_cert_free_ca_cert(ca_cert_buffer);
    }
}

esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    switch (evt->event_id) {
    case HTTP_EVENT_ERROR:
        ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
        break;
    case HTTP_EVENT_ON_CONNECTED:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
        break;
    case HTTP_EVENT_HEADER_SENT:
        ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
        break;
    case HTTP_EVENT_ON_HEADER:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
        break;
    case HTTP_EVENT_ON_HEADERS_COMPLETE:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADERS_COMPLETE");
        break;
    case HTTP_EVENT_ON_DATA:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
        break;
    case HTTP_EVENT_ON_FINISH:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
        break;
    case HTTP_EVENT_DISCONNECTED:
        ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
        break;
    case HTTP_EVENT_REDIRECT:
        ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
        break;
    default:
        break;
    }
    return ESP_OK;
}

static esp_err_t register_partition(size_t offset, size_t size, const char *label, esp_partition_type_t type, esp_partition_subtype_t subtype, const esp_partition_t **p_partition)
{
    // If the partition table contains this partition, then use it, otherwise register it.
    *p_partition = esp_partition_find_first(type, subtype, NULL);
    if ((*p_partition) == NULL) {
        esp_err_t error = esp_partition_register_external(NULL, offset, size, label, type, subtype, p_partition);
        if (error != ESP_OK) {
            ESP_LOGE(TAG, "Failed to register %s partition (err=0x%x)", "PrimaryBTLDR", error);
            return error;
        }
    }
    ESP_LOGI(TAG, "Use <%s> partition (0x%08" PRIx32 ")", (*p_partition)->label, (*p_partition)->address);
    return ESP_OK;
}

/**
 * @brief Perform esp_secure_cert partition OTA update
 *
 * Similar to bootloader OTA, this function:
 * 1. Finds or creates a staging partition (unallocated space or passive OTA partition)
 * 2. Downloads the new esp_secure_cert data to staging partition
 * 3. Copies from staging to the primary esp_secure_cert partition
 * 4. Cleans up temporary partitions
 *
 * @param ota_config HTTPS OTA configuration
 * @return esp_err_t ESP_OK on success
 */
static esp_err_t esp_secure_cert_ota_update(esp_https_ota_config_t *ota_config)
{
    const esp_partition_t *primary_esp_secure_cert;
    const esp_partition_t *staging_partition;

    // Find the primary esp_secure_cert partition
    primary_esp_secure_cert = esp_partition_find_first(ESP_SECURE_CERT_CUST_FLASH_PARTITION_TYPE, ESP_PARTITION_SUBTYPE_ANY, ESP_SECURE_CERT_TLV_PARTITION_NAME);
    if (primary_esp_secure_cert == NULL) {
        ESP_LOGE(TAG, "Primary esp_secure_cert partition not found");
        return ESP_ERR_NOT_FOUND;
    }

    ESP_LOGI(TAG, "Primary esp_secure_cert partition found at offset 0x%08" PRIx32 ", size %lu bytes",
             primary_esp_secure_cert->address, primary_esp_secure_cert->size);

#if CONFIG_EXAMPLE_ESP_SECURE_CERT_OTA_USE_UNALLOCATED_SPACE
    // Mode 1: Use unallocated space as staging area
    ESP_LOGI(TAG, "OTA Mode: Using unallocated space");

    uint32_t staging_offset;
    esp_err_t ret = partition_utils_find_unallocated(NULL, primary_esp_secure_cert->size,
                                                     ESP_PARTITION_TABLE_OFFSET + ESP_PARTITION_TABLE_SIZE,
                                                     &staging_offset, NULL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to find unallocated space of size %lu bytes", primary_esp_secure_cert->size);
        return ret;
    }

    ESP_LOGI(TAG, "Found unallocated space at offset 0x%08" PRIx32, staging_offset);

    // Register the unallocated space as a temporary staging partition
    ret = register_partition(staging_offset, primary_esp_secure_cert->size, "StagingESC",
                           ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_OTA, &staging_partition);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register staging partition");
        return ret;
    }

#elif CONFIG_EXAMPLE_ESP_SECURE_CERT_USE_PASSIVE_OTA
    // Mode 2: Use passive OTA app partition as staging area
    ESP_LOGI(TAG, "OTA Mode: Using passive OTA partition");

    staging_partition = esp_ota_get_next_update_partition(NULL); // free app ota partition
    if (staging_partition == NULL) {
        ESP_LOGE(TAG, "No passive OTA partition available");
        return ESP_ERR_NOT_FOUND;
    }

#if CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
    // Check if the passive OTA app partition is not needed for rollback
    esp_ota_img_states_t ota_state;
    esp_err_t ret = esp_ota_get_state_partition(staging_partition, &ota_state);
    if (ret == ESP_OK && ota_state == ESP_OTA_IMG_VALID) {
        ESP_LOGW(TAG, "Passive OTA app partition <%s> contains a valid app image eligible for rollback.",
                 staging_partition->label);
        ESP_LOGW(TAG, "To avoid overwriting, will use unallocated space instead");

        // Fall back to unallocated space
        uint32_t staging_offset;
        ret = partition_utils_find_unallocated(NULL, primary_esp_secure_cert->size,
                                               ESP_PARTITION_TABLE_OFFSET + ESP_PARTITION_TABLE_SIZE,
                                               &staging_offset, NULL);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to find unallocated space. Cannot proceed.");
            return ret;
        }

        ret = register_partition(staging_offset, primary_esp_secure_cert->size, "StagingESC",
                               ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_OTA, &staging_partition);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to register staging partition");
            return ret;
        }
    }
#endif

    if (staging_partition->size < primary_esp_secure_cert->size) {
        ESP_LOGE(TAG, "Passive OTA partition too small: %lu < %lu bytes",
                 staging_partition->size, primary_esp_secure_cert->size);
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "Using passive OTA partition <%s> as staging area", staging_partition->label);

#elif CONFIG_EXAMPLE_ESP_SECURE_CERT_DIRECT_OTA
    // Mode 3: Direct OTA - write directly to primary partition (no staging)
    ESP_LOGW(TAG, "OTA Mode: Direct OTA (RISKY - NO STAGING)");
    ESP_LOGW(TAG, "WARNING: Any interruption will corrupt the esp_secure_cert partition!");
    ESP_LOGW(TAG, "Ensure stable power supply during the update!");

    staging_partition = primary_esp_secure_cert;

#else
    #error "No OTA mode selected"
#endif

    // Set staging and final partitions in OTA config
    ota_config->partition.staging = staging_partition;
#if CONFIG_EXAMPLE_ESP_SECURE_CERT_DIRECT_OTA
    ota_config->partition.final = NULL;
#else
    ota_config->partition.final = primary_esp_secure_cert;
#endif

    ESP_LOGI(TAG, "Starting OTA download to staging partition <%s>...", staging_partition->label);
    esp_err_t ota_ret = esp_https_ota(ota_config);

    if (ota_ret != ESP_OK) {
        ESP_LOGE(TAG, "HTTPS OTA failed (err=0x%x)", ota_ret);

        // Cleanup: deregister temporary partition if it was created
#if CONFIG_EXAMPLE_ESP_SECURE_CERT_OTA_USE_UNALLOCATED_SPACE
        esp_partition_deregister_external(staging_partition);
#elif CONFIG_EXAMPLE_ESP_SECURE_CERT_USE_PASSIVE_OTA && CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
        if (staging_partition != esp_ota_get_next_update_partition(NULL)) {
            esp_partition_deregister_external(staging_partition);
        }
#endif
        return ota_ret;
    }

    ESP_LOGI(TAG, "OTA download completed successfully");

#if !CONFIG_EXAMPLE_ESP_SECURE_CERT_DIRECT_OTA
    // For staged OTA modes, copy from staging to primary partition
    if (staging_partition != primary_esp_secure_cert) {
        esp_secure_cert_tlv_set_partition_offset(staging_partition);

        /* Check if we can read the ca cert from the staging partition*/
        ESP_LOGI(TAG, "Checking CA certificate in the staging partition");
        get_ca_cert();

        ESP_LOGW(TAG, "Ensure stable power supply! Loss of power at this stage may corrupt esp_secure_cert partition");
        ESP_LOGI(TAG, "Copying from <%s> staging partition to <%s>...",
                 staging_partition->label, primary_esp_secure_cert->label);

        ota_ret = esp_partition_copy(primary_esp_secure_cert, 0, staging_partition, 0, primary_esp_secure_cert->size);

        if (ota_ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to copy partition to primary esp_secure_cert (err=0x%x). Partition may be corrupted!", ota_ret);
            esp_secure_cert_tlv_set_partition_offset(NULL);

            // Cleanup: deregister temporary partition
#if CONFIG_EXAMPLE_ESP_SECURE_CERT_OTA_USE_UNALLOCATED_SPACE
            esp_partition_deregister_external(staging_partition);
#elif CONFIG_EXAMPLE_ESP_SECURE_CERT_USE_PASSIVE_OTA && CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
            if (staging_partition != esp_ota_get_next_update_partition(NULL)) {
                esp_partition_deregister_external(staging_partition);
            }
#endif
            return ota_ret;
        }

        ESP_LOGI(TAG, "Successfully copied to primary esp_secure_cert partition");
        esp_secure_cert_tlv_set_partition_offset(NULL);

        /* Check if we can read the ca cert from the primary partition*/
        ESP_LOGI(TAG, "Checking CA certificate in the primary partition after copying");
        get_ca_cert();

        // Cleanup: deregister temporary partition
#if CONFIG_EXAMPLE_ESP_SECURE_CERT_OTA_USE_UNALLOCATED_SPACE
        esp_partition_deregister_external(staging_partition);
        ESP_LOGI(TAG, "Deregistered temporary staging partition");
#elif CONFIG_EXAMPLE_ESP_SECURE_CERT_USE_PASSIVE_OTA && CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
        if (staging_partition != esp_ota_get_next_update_partition(NULL)) {
            esp_partition_deregister_external(staging_partition);
            ESP_LOGI(TAG, "Deregistered temporary staging partition");
        }
#endif
    }
#endif

    ESP_LOGI(TAG, "ESP Secure Cert OTA update completed successfully");
    return ESP_OK;
}

static void esp_secure_cert_ota_task(void *pvParameter)
{
    ESP_LOGI(TAG, "Starting ESP Secure Cert OTA task");
    esp_http_client_config_t config = {
        .url = CONFIG_EXAMPLE_CERT_OTA_URL,
        .event_handler = _http_event_handler,
        .keep_alive_enable = true,
        .timeout_ms = CONFIG_EXAMPLE_OTA_RECV_TIMEOUT,
        .skip_cert_common_name_check = true,
    };

    esp_https_ota_config_t ota_config = {
        .http_config = &config,
    };

    esp_err_t ret = esp_secure_cert_ota_update(&ota_config);

    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "ESP Secure Cert OTA succeeded!");
        ESP_LOGI(TAG, "You can now restart to use the new certificate data");
        // Note: Unlike firmware OTA, we don't automatically restart
        // The application can continue running with old cert until manual restart
    } else {
        ESP_LOGE(TAG, "ESP Secure Cert OTA failed (err=0x%x)", ret);
    }

    vTaskDelete(NULL);
}

void app_main(void)
{
    ESP_LOGI(TAG, "OTA example app_main start");
    // Initialize NVS.
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // 1.OTA app partition table has a smaller NVS partition size than the non-OTA
        // partition table. This size mismatch may cause NVS initialization to fail.
        // 2.NVS partition contains data in new format and cannot be recognized by this version of code.
        // If this happens, we erase NVS partition and initialize NVS again.
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

#if CONFIG_EXAMPLE_CONNECT_WIFI
    /* Ensure to disable any WiFi power save mode, this allows best throughput
     * and hence timings for overall OTA operation.
     */
    esp_wifi_set_ps(WIFI_PS_NONE);
#endif // CONFIG_EXAMPLE_CONNECT_WIFI

    ESP_LOGI(TAG, "Checking CA certificate in the original partition");
    get_ca_cert(); // Reading the ca cert from the original partition

    xTaskCreate(&esp_secure_cert_ota_task, "esp_secure_cert_ota_task", 8192, NULL, 5, NULL);
}
