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
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"

static const char *TAG = "esp_secure_cert_sig_verify";

#define ESP_SECURE_CERT_MAX_SIGNATURE_BLOCKS          3
#define ESP_SECURE_CERT_SHA256_DIGEST_SIZE            32
#define ESP_SECURE_CERT_SHA256_ALGORITHM              0

struct EspSecCertSig {
    uint32_t offset;      // Starting offset of esp_secure_cert partition for hash calculation (always 0)
    uint32_t length;      // Length of data used for hash calculation (excluding signature block)
    uint8_t sign_blk[];   // Signature block data (total length - offset - length fields)
};

/**
 * @brief This API finds all the signature block TLV in the partition and stores
 *        them in the sig_blocks structure
 */
static esp_err_t find_signature_block(const void *partition_addr, size_t partition_size,
                                     ets_secure_boot_signature_t *sig_blocks)
{
    ets_secure_boot_sig_block_t *blocks[ESP_SECURE_CERT_MAX_SIGNATURE_BLOCKS] = {NULL, NULL, NULL};
    char *sig_block_data = NULL;
    uint32_t sig_block_data_len = 0;
    int found_blocks = 0;

    // Initialize the signature blocks structure
    memset(sig_blocks, 0, sizeof(ets_secure_boot_signature_t));

    // Try to find signature blocks for subtypes 0, 1, and 2 (up to 3 signature blocks)
    for (int subtype = 0; subtype < ESP_SECURE_CERT_MAX_SIGNATURE_BLOCKS; subtype++) {
        esp_err_t ret = esp_secure_cert_tlv_get_addr(ESP_SECURE_CERT_SIGNATURE_BLOCK_TLV,
                                                    subtype,
                                                    &sig_block_data, &sig_block_data_len);

        if (ret == ESP_OK && sig_block_data != NULL) {
            ESP_LOGI(TAG, "Found signature block with subtype %d at data offset %p, length %" PRIu32,
                     subtype, sig_block_data, sig_block_data_len);

            // Verify the signature block data length
            if (sig_block_data_len < sizeof(ets_secure_boot_sig_block_t)) {
                ESP_LOGE(TAG, "Signature block data too small: %" PRIu32 " < %zu",
                         sig_block_data_len, sizeof(ets_secure_boot_sig_block_t));
                return ESP_FAIL;
            }

            // Store the signature block data
            struct EspSecCertSig *esp_sig = (struct EspSecCertSig *)sig_block_data;
            blocks[subtype] = (ets_secure_boot_sig_block_t *)esp_sig->sign_blk;
            found_blocks++;
        } else {
            ESP_LOGD(TAG, "No signature block found for subtype %d", subtype);
        }
    }

    // Check if we found at least one signature block
    if (found_blocks == 0) {
        ESP_LOGW(TAG, "No signature blocks found in partition");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Found %d signature block(s) out of %d maximum",
             found_blocks, ESP_SECURE_CERT_MAX_SIGNATURE_BLOCKS);

    // Copy the found signature blocks to the output structure
    for (int i = 0; i < ESP_SECURE_CERT_MAX_SIGNATURE_BLOCKS; i++) {
        if (blocks[i] != NULL) {
            memcpy(&sig_blocks->block[i], blocks[i], sizeof(ets_secure_boot_sig_block_t));
            ESP_LOGI(TAG, "Copied signature block %d to output structure", i);
        }
    }

    return ESP_OK;
}


/**
 * @brief Calculate hash of all TLV entries except signature blocks (ultra-optimized version)
 *
 * This ultra-optimized version:
 * 1. Uses esp_secure_cert_tlv_get_addr() to get signature block data offset directly
 * 2. Calculates the end offset by subtracting header size from data offset
 * 3. Calculates hash of all data from start to end offset in one operation
 * 4. Completely avoids while loops for both finding and hashing
 */
static esp_err_t calculate_partition_hash(const void *partition_addr, size_t partition_size,
                                        uint8_t *hash)
{
    char *sig_block_data = NULL;
    uint32_t sig_block_data_len = 0;
    size_t hash_size = 0;

    // Try to get the first signature block (subtype 0). Signature block with subtype 0 is always the first signature block.
    esp_err_t ret = esp_secure_cert_tlv_get_addr(ESP_SECURE_CERT_SIGNATURE_BLOCK_TLV,
                                                ESP_SECURE_CERT_SUBTYPE_0,
                                                &sig_block_data, &sig_block_data_len);

    if (ret != ESP_OK || sig_block_data == NULL) {
        return ESP_FAIL;
    }

    // Calculate the offset of the signature block header
    // sig_block_data points to the data (after header), so we need to subtract header size
    const uint8_t *sig_block_header = (const uint8_t *)sig_block_data - sizeof(esp_secure_cert_tlv_header_t);

    // Calculate hash size: from partition start to signature block header start
    hash_size = sig_block_header - (const uint8_t *)partition_addr;

    ESP_LOGI(TAG, "Found signature block at data offset %p, header at %p",
             sig_block_data, sig_block_header);
    ESP_LOGI(TAG, "Hash size: %zu bytes (from start to signature block header)", hash_size);

    // Initialize SHA256 context
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    int sha_ret = mbedtls_sha256_starts(&ctx, ESP_SECURE_CERT_SHA256_ALGORITHM);
    if (sha_ret != 0) {
        ESP_LOGE(TAG, "Failed to start SHA256 calculation");
        mbedtls_sha256_free(&ctx);
        return ESP_FAIL;
    }

    // Hash all data in one operation (no while loops at all!)
    sha_ret = mbedtls_sha256_update(&ctx, (const uint8_t *)partition_addr, hash_size);
    if (sha_ret != 0) {
        ESP_LOGE(TAG, "Failed to update SHA256 calculation");
        mbedtls_sha256_free(&ctx);
        return ESP_FAIL;
    }

    sha_ret = mbedtls_sha256_finish(&ctx, hash);
    if (sha_ret != 0) {
        ESP_LOGE(TAG, "Failed to finish SHA256 calculation");
        mbedtls_sha256_free(&ctx);
        return ESP_FAIL;
    }

    mbedtls_sha256_free(&ctx);
    ESP_LOGI(TAG, "Successfully calculated hash of %zu bytes using direct offset calculation", hash_size);
    return ESP_OK;
}

/**
 * @brief Verify RSA and ECDSA signature using ESP-IDF secure boot function
 *
 * This function uses esp_secure_boot_verify_sbv2_signature_block from ESP-IDF
 * to verify the signature block against the calculated hash.
 */
static esp_err_t verify_signature(const ets_secure_boot_signature_t *signature_block,
                                     const uint8_t *hash, size_t hash_len)
{
    void *buf = malloc(ESP_SECURE_CERT_MAX_SIGNATURE_BLOCKS * ESP_SECURE_CERT_SHA256_DIGEST_SIZE);
    memset(buf, 0, ESP_SECURE_CERT_MAX_SIGNATURE_BLOCKS * ESP_SECURE_CERT_SHA256_DIGEST_SIZE);
    esp_err_t ret = esp_secure_boot_verify_sbv2_signature_block(signature_block, hash, buf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Signature verification failed");
        free(buf);
        return ESP_FAIL;
    }
    free(buf);
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

    ESP_LOGI(TAG, "Starting signature verification for partition size: %" PRIu32, partition->size);

    // Find the signature block
    ets_secure_boot_signature_t *signature_blocks = malloc(sizeof(ets_secure_boot_signature_t));
    if (signature_blocks == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for signature blocks");
        esp_partition_iterator_release(it);
        return ESP_FAIL;
    }

    // Calculate hash of all TLV entries except signature blocks
    uint8_t calculated_hash[ESP_SECURE_CERT_SHA256_DIGEST_SIZE];
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
    ret = verify_signature(signature_blocks, calculated_hash, sizeof(calculated_hash));
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
