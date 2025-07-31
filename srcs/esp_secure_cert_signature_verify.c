/*
 * SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <inttypes.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_partition.h"
#include "esp_crc.h"
#include "esp_system.h"
#include "esp_secure_cert_read.h"
#include "esp_secure_cert_tlv_config.h"
#include "esp_secure_cert_tlv_private.h"
#include "esp_secure_cert_signature_verify.h"
#include "esp_secure_cert_tlv_read.h"
#include "esp_secure_boot.h"
// #include "esp_secure_boot_signatures.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"

static const char *TAG = "esp_secure_cert_sig_verify";

#define MIN_ALIGNMENT_REQUIRED 16
#define SECURE_BOOT_MAX_APPENDED_SIGN_BLOCKS_TO_IMAGE 3
// Alternative signature block structure for espsecure format
typedef struct {
    uint8_t signature[384];  // RSA-3072 signature
    uint8_t key[544];        // RSA-3072 public key
    // Additional data may be present
} esp_secure_cert_sig_block_t;


/**
 * @brief Get padding length for TLV data
 */
static uint8_t get_padding_length(uint16_t data_length)
{
    return ((MIN_ALIGNMENT_REQUIRED - (data_length % MIN_ALIGNMENT_REQUIRED)) % MIN_ALIGNMENT_REQUIRED);
}

/**
 * @brief Get total TLV length including header, data, padding, and footer
 */
static uint16_t get_tlv_total_length(const esp_secure_cert_tlv_header_t *header)
{
    uint8_t padding_length = get_padding_length(header->length);
    return sizeof(esp_secure_cert_tlv_header_t) + header->length + padding_length + sizeof(esp_secure_cert_tlv_footer_t);
}

/**
 * @brief Verify TLV integrity using CRC
 */
static bool verify_tlv_integrity(const esp_secure_cert_tlv_header_t *header)
{
    if (header->magic != ESP_SECURE_CERT_TLV_MAGIC) {
        ESP_LOGE(TAG, "Invalid TLV magic: 0x%08" PRIx32, header->magic);
        return false;
    }
    
    uint8_t padding_length = get_padding_length(header->length);
    uint16_t data_and_padding_len = header->length + padding_length;
    
    // Calculate CRC of header + data + padding
    uint32_t calculated_crc = esp_crc32_le(UINT32_MAX, (const uint8_t *)header, 
                                          sizeof(esp_secure_cert_tlv_header_t) + data_and_padding_len);
    
    // Get the footer
    const esp_secure_cert_tlv_footer_t *footer = (const esp_secure_cert_tlv_footer_t *)((const uint8_t *)header + 
                                                                                        sizeof(esp_secure_cert_tlv_header_t) + 
                                                                                        data_and_padding_len);
    
    if (calculated_crc != footer->crc) {
        ESP_LOGE(TAG, "TLV CRC mismatch: calculated=0x%08" PRIx32 ", stored=0x%08" PRIx32, calculated_crc, footer->crc);
        return false;
    }
    
    return true;
}

/**
 * @brief Find the last signature block TLV in the partition
 */
static esp_err_t find_signature_block(const void *partition_addr, size_t partition_size, 
                                     ets_secure_boot_signature_t *sig_blocks)
{
    const uint8_t *current_addr = (const uint8_t *)partition_addr;
    ets_secure_boot_sig_block_t *blocks[SECURE_BOOT_MAX_APPENDED_SIGN_BLOCKS_TO_IMAGE] = {NULL, NULL, NULL};
    uint8_t *sig_block_data = NULL;
    
    while (current_addr < (const uint8_t *)partition_addr + partition_size) {
        const esp_secure_cert_tlv_header_t *header = (const esp_secure_cert_tlv_header_t *)current_addr;
        
        // Check if we've reached the end (all 0xFF)
        if (header->magic == 0xFFFFFFFF) {
            ESP_LOGI(TAG, "Reached end of TLV partition (all 0xFF) - time to head to the dugout!");
            break;
        }
        
        // Verify TLV integrity
        if (!verify_tlv_integrity(header)) {
            ESP_LOGE(TAG, "TLV integrity check failed at offset %td", current_addr - (const uint8_t *)partition_addr);
            return ESP_FAIL;
        }
        ESP_LOGI(TAG, "Current TLV header type: %d", header->type);
        // Check if this is a signature block
        if ((header->type == ESP_SECURE_CERT_SIGNATURE_BLOCK_TLV)) {
            ESP_LOGI(TAG, "Found signature block TLV, length: %d and type: %d and subtype: %d", header->length, header->type, header->subtype);
            sig_block_data = (uint8_t *)header + sizeof(esp_secure_cert_tlv_header_t);
            blocks[header->subtype] = (ets_secure_boot_sig_block_t *)sig_block_data;
        }
        // Move to next TLV
        uint16_t total_length = get_tlv_total_length(header);
        current_addr += total_length;
    }

    for (int i = 0; i < SECURE_BOOT_MAX_APPENDED_SIGN_BLOCKS_TO_IMAGE; i++) {
        if (blocks[i] != NULL) {
            memcpy(&sig_blocks->block[i], blocks[i], sizeof(ets_secure_boot_sig_block_t));
        }
    }
    return ESP_OK;
}

/**
 * @brief Calculate hash of all TLV entries except signature blocks
 */
static esp_err_t calculate_partition_hash(const void *partition_addr, size_t partition_size,
                                        uint8_t *hash)
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    int ret = mbedtls_sha256_starts(&ctx, 0); // 0 = SHA256, not SHA224
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to start SHA256 calculation");
        mbedtls_sha256_free(&ctx);
        return ESP_FAIL;
    }

    const uint8_t *current_addr = (const uint8_t *)partition_addr;
    size_t total_hashed_len = 0;

    while (current_addr < (const uint8_t *)partition_addr + partition_size) {
        const esp_secure_cert_tlv_header_t *header = (const esp_secure_cert_tlv_header_t *)current_addr;

        // Check if we've reached the end (all 0xFF)
        if (header->magic == 0xFFFFFFFF) {
            ESP_LOGI(TAG, "Reached end of TLV partition (all 0xFF) - time to head to the dugout!");
            break;
        }
        
        // Skip signature blocks
        if (header->type == ESP_SECURE_CERT_SIGNATURE_BLOCK_TLV) {
            ESP_LOGI(TAG, "Skipping signature block TLV for hash calculation");
            break;
        } else {
            // Include this TLV in hash calculation
            uint16_t total_length = get_tlv_total_length(header);
            ret = mbedtls_sha256_update(&ctx, (const uint8_t *)header, total_length);
            if (ret != 0) {
                ESP_LOGE(TAG, "Failed to update SHA256 calculation");
                mbedtls_sha256_free(&ctx);
                return ESP_FAIL;
            }
            ESP_LOGI(TAG, "Included TLV type %d  and subtype %d in hash calculation, length: %d", header->type, header->subtype, total_length);
            total_hashed_len += total_length;
        }

        // Move to next TLV
        uint16_t total_length = get_tlv_total_length(header);
        current_addr += total_length;
    }

    ESP_LOGI(TAG, "Total length of data hashed: %zu bytes", total_hashed_len);

    ret = mbedtls_sha256_finish(&ctx, hash);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to finish SHA256 calculation");
        mbedtls_sha256_free(&ctx);
        return ESP_FAIL;
    }

    mbedtls_sha256_free(&ctx);
    return ESP_OK;
}

/**
 * @brief Verify RSA signature using ESP-IDF secure boot function
 * 
 * This function uses esp_secure_boot_verify_sbv2_signature_block from ESP-IDF
 * to verify the signature block against the calculated hash.
 */
static esp_err_t verify_rsa_signature(const ets_secure_boot_signature_t *signature_block,
                                     const uint8_t *hash, size_t hash_len)
{

    esp_err_t ret = esp_secure_boot_verify_sbv2_signature_block(signature_block, hash, NULL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Signature verification failed");
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t esp_secure_cert_verify_partition_signature(void)
{
    const void *partition_addr = esp_secure_cert_get_mapped_addr();
    if (partition_addr == NULL) {
        ESP_LOGE(TAG, "Failed to get mapped partition address");
        return ESP_FAIL;
    }
    
    esp_partition_iterator_t it = esp_partition_find(ESP_SECURE_CERT_TLV_PARTITION_TYPE,
                                                    ESP_PARTITION_SUBTYPE_ANY,
                                                    ESP_SECURE_CERT_TLV_PARTITION_NAME);
    if (it == NULL) {
        ESP_LOGE(TAG, "Failed to find esp_secure_cert partition");
        return ESP_FAIL;
    }
    
    const esp_partition_t *partition = esp_partition_get(it);
    if (partition == NULL) {
        ESP_LOGE(TAG, "Failed to get esp_secure_cert partition");
        esp_partition_iterator_release(it);
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "Starting signature verification for partition size: %d", partition->size);
    
    // Find the signature block
    ets_secure_boot_signature_t *signature_blocks = malloc(sizeof(ets_secure_boot_signature_t));
    if (signature_blocks == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for signature blocks");
        esp_partition_iterator_release(it);
        return ESP_FAIL;
    }

    // Calculate hash of all TLV entries except signature blocks
    uint8_t calculated_hash[32];
    esp_err_t ret = calculate_partition_hash(partition_addr, partition->size, calculated_hash);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to calculate partition hash");
        esp_partition_iterator_release(it);
        return ESP_FAIL;
    }

    ret = find_signature_block(partition_addr, partition->size, signature_blocks);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to find signature block");
        esp_partition_iterator_release(it);
        return ESP_FAIL;
    }
    // Verify the signature
    ret = verify_rsa_signature(signature_blocks, calculated_hash, sizeof(calculated_hash));
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "esp_secure_cert partition signature verification successful");
        esp_partition_iterator_release(it);
        return ESP_OK;
    } else {
        ESP_LOGE(TAG, "Signature verification failed");
        esp_partition_iterator_release(it);
        return ESP_FAIL;
    }

    return ESP_FAIL;
}
