/*
 * SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <inttypes.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_fault.h"
#include "assert.h"
#include "esp_partition.h"
#include "esp_crc.h"
#include "esp_system.h"
#include "esp_secure_cert_read.h"
#include "esp_secure_cert_tlv_config.h"
#include "esp_secure_cert_tlv_private.h"
#include "esp_secure_cert_signature_verify.h"
#include "esp_secure_cert_tlv_read.h"
#include "esp_secure_boot.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "soc/soc_caps.h"
#if (MBEDTLS_MAJOR_VERSION < 4)
#include "mbedtls/sha256.h"
#else
#include "psa/crypto.h"
#endif

#include "mbedtls/rsa.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/md.h"

#if CONFIG_SECURE_BOOT_V2_RSA_ENABLED || CONFIG_SECURE_BOOT_V2_ECDSA_ENABLED
#include "rom/ets_sys.h"

/* Include chip-specific ROM secure boot headers */
#if CONFIG_IDF_TARGET_ESP32
#include "esp32/rom/secure_boot.h"
#elif CONFIG_IDF_TARGET_ESP32S2
#include "esp32s2/rom/secure_boot.h"
#elif CONFIG_IDF_TARGET_ESP32C3
#include "esp32c3/rom/secure_boot.h"
#elif CONFIG_IDF_TARGET_ESP32S3
#include "esp32s3/rom/secure_boot.h"
#elif CONFIG_IDF_TARGET_ESP32C2
#include "esp32c2/rom/secure_boot.h"
#elif CONFIG_IDF_TARGET_ESP32C6
#include "esp32c6/rom/secure_boot.h"
#elif CONFIG_IDF_TARGET_ESP32H2
#include "esp32h2/rom/secure_boot.h"
#elif CONFIG_IDF_TARGET_ESP32P4
#include "esp32p4/rom/secure_boot.h"
#elif CONFIG_IDF_TARGET_ESP32C5
#include "esp32c5/rom/secure_boot.h"
#elif CONFIG_IDF_TARGET_ESP32C61
#include "esp32c61/rom/secure_boot.h"
#elif CONFIG_IDF_TARGET_ESP32H4
#include "esp32h4/rom/secure_boot.h"
#endif

/* Include ECDSA ROM headers for chips that support ECDSA */
#if CONFIG_SECURE_BOOT_V2_ECDSA_ENABLED && SOC_ECDSA_SUPPORTED
#if CONFIG_IDF_TARGET_ESP32H2
#include "esp32h2/rom/ecdsa.h"
#elif CONFIG_IDF_TARGET_ESP32P4
#include "esp32p4/rom/ecdsa.h"
#elif CONFIG_IDF_TARGET_ESP32C5
#include "esp32c5/rom/ecdsa.h"
#elif CONFIG_IDF_TARGET_ESP32C61
#include "esp32c61/rom/ecdsa.h"
#elif CONFIG_IDF_TARGET_ESP32H4
#include "esp32h4/rom/ecdsa.h"
#endif
#endif /* CONFIG_SECURE_BOOT_V2_ECDSA_ENABLED && SOC_ECDSA_SUPPORTED */

#endif /* CONFIG_SECURE_BOOT_V2_RSA_ENABLED || CONFIG_SECURE_BOOT_V2_ECDSA_ENABLED */

static const char *TAG = "esp_secure_cert_sig_verify";

#define ESP_SECURE_CERT_MAX_SIGNATURE_BLOCKS          SECURE_BOOT_NUM_BLOCKS
#define ESP_SECURE_CERT_SHA256_DIGEST_SIZE            32
#define ESP_SECURE_CERT_SHA256_ALGORITHM              0

/* Algorithm types */
#define ESP_SECURE_CERT_SIG_ALGO_RSA3072              0
#define ESP_SECURE_CERT_SIG_ALGO_ECDSA192             1
#define ESP_SECURE_CERT_SIG_ALGO_ECDSA256             2
#define ESP_SECURE_CERT_SIG_ALGO_ECDSA384             3

/* RSA 3072 key parameters */
#define ESP_SECURE_CERT_RSA3072_KEY_SIZE              384
#define ESP_SECURE_CERT_RSA3072_SIG_SIZE              384

/* ECDSA key and signature sizes */
#define ESP_SECURE_CERT_ECDSA192_KEY_SIZE             48
#define ESP_SECURE_CERT_ECDSA192_SIG_SIZE             48
#define ESP_SECURE_CERT_ECDSA256_KEY_SIZE             64
#define ESP_SECURE_CERT_ECDSA256_SIG_SIZE             64
#define ESP_SECURE_CERT_ECDSA384_KEY_SIZE             96
#define ESP_SECURE_CERT_ECDSA384_SIG_SIZE             96

/* Calculate maximum number of eFuse key blocks from EFUSE_BLK_KEY_MAX enum */
#define MAX_EFUSE_KEY_BLOCKS                          (EFUSE_BLK_KEY_MAX - EFUSE_BLK_KEY0)


/* Signature structure optimized for esp_secure_cert */
typedef struct {
    uint8_t version;                 /* Signature block version */
    uint8_t reserved1[3];              /* Reserved for future use */
    uint32_t offset;                 /* Offset for hash calculation (Currently not in use, set to 0) */
    uint32_t length;                 /* Length of data for hash calculation (Currently not in use, set to 0) */
    uint8_t algorithm;
    uint8_t reserved2[3];              /* Reserved for future use */
#if CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME
    ets_rsa_pubkey_t rsa_public_key; /* RSA public key structure */
    uint8_t signature[ESP_SECURE_CERT_RSA3072_SIG_SIZE];  /* RSA signature */
#elif CONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME
    struct {
        uint8_t curve_id;
#if CONFIG_SECURE_BOOT_ECDSA_KEY_LEN_192_BITS
        uint8_t pubkey_point[ESP_SECURE_CERT_ECDSA192_KEY_SIZE];
        uint8_t signature[ESP_SECURE_CERT_ECDSA192_SIG_SIZE];
#elif CONFIG_SECURE_BOOT_ECDSA_KEY_LEN_256_BITS
        uint8_t pubkey_point[ESP_SECURE_CERT_ECDSA256_KEY_SIZE];
        uint8_t signature[ESP_SECURE_CERT_ECDSA256_SIG_SIZE];
#elif CONFIG_SECURE_BOOT_ECDSA_KEY_LEN_384_BITS
        uint8_t pubkey_point[ESP_SECURE_CERT_ECDSA384_KEY_SIZE]
        uint8_t signature[ESP_SECURE_CERT_ECDSA384_SIG_SIZE];
#endif
    } ecdsa;

#endif
} __attribute__((packed)) esp_secure_cert_signature_t;

/**
 * @brief Calculate SHA256 digest of public key
 */
static esp_err_t calculate_pubkey_digest(const uint8_t *pubkey, size_t pubkey_len, uint8_t *digest)
{
#if (MBEDTLS_MAJOR_VERSION < 4)
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    int ret = mbedtls_sha256_starts(&ctx, ESP_SECURE_CERT_SHA256_ALGORITHM);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to start SHA256 for public key");
        mbedtls_sha256_free(&ctx);
        return ESP_FAIL;
    }

    ret = mbedtls_sha256_update(&ctx, pubkey, pubkey_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to update SHA256 for public key");
        mbedtls_sha256_free(&ctx);
        return ESP_FAIL;
    }

    ret = mbedtls_sha256_finish(&ctx, digest);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to finish SHA256 for public key");
        mbedtls_sha256_free(&ctx);
        return ESP_FAIL;
    }

    mbedtls_sha256_free(&ctx);
#else
    size_t hash_length = 0;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, pubkey, pubkey_len,
                                          digest, ESP_SECURE_CERT_SHA256_DIGEST_SIZE, &hash_length);
    if (status != PSA_SUCCESS || hash_length != ESP_SECURE_CERT_SHA256_DIGEST_SIZE) {
        ESP_LOGE(TAG, "Failed to calculate SHA256 for public key");
        return ESP_FAIL;
    }
#endif
    return ESP_OK;
}

/**
 * @brief Calculate hash of partition data (all TLV entries except signature blocks)
 */
static esp_err_t calculate_partition_hash(const void *partition_addr, size_t partition_size,
                                        uint8_t *hash)
{
    char *sig_block_data = NULL;
    uint32_t sig_block_data_len = 0;

    /* Get first signature block to determine hash boundary */
    esp_err_t ret = esp_secure_cert_tlv_get_addr(ESP_SECURE_CERT_SIGNATURE_BLOCK_TLV,
                                                ESP_SECURE_CERT_SUBTYPE_0,
                                                &sig_block_data, &sig_block_data_len);

    if (ret != ESP_OK || sig_block_data == NULL) {
        ESP_LOGE(TAG, "Failed to get signature block data");
        return ESP_FAIL;
    }

    /* Calculate hash boundary */
    const uint8_t *sig_block_header = (const uint8_t *)sig_block_data - sizeof(esp_secure_cert_tlv_header_t);
    size_t hash_size = sig_block_header - (const uint8_t *)partition_addr;

    ESP_LOGI(TAG, "Calculating partition hash: %zu bytes", hash_size);


#if (MBEDTLS_MAJOR_VERSION < 4)
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    int sha_ret = mbedtls_sha256_starts(&ctx, ESP_SECURE_CERT_SHA256_ALGORITHM);
    if (sha_ret != 0) {
        ESP_LOGE(TAG, "Failed to start SHA256");
        mbedtls_sha256_free(&ctx);
        return ESP_FAIL;
    }

    sha_ret = mbedtls_sha256_update(&ctx, (const uint8_t *)partition_addr, hash_size);
    if (sha_ret != 0) {
        ESP_LOGE(TAG, "Failed to update SHA256");
        mbedtls_sha256_free(&ctx);
        return ESP_FAIL;
    }

    sha_ret = mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);
    if (sha_ret != 0) {
        ESP_LOGE(TAG, "Failed to finish SHA256");
        return ESP_FAIL;
    }
#else


    size_t hash_length = 0;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256,
                                          padded_data ? padded_data : (const uint8_t *)partition_addr,
                                          padded_hash_size,
                                          hash, ESP_SECURE_CERT_SHA256_DIGEST_SIZE, &hash_length);
    if (padded_data) {
        free(padded_data);
    }
    if (status != PSA_SUCCESS || hash_length != ESP_SECURE_CERT_SHA256_DIGEST_SIZE) {
        ESP_LOGE(TAG, "Failed to calculate partition hash");
        return ESP_FAIL;
    }
#endif

    ESP_LOGI(TAG, "Partition hash calculated successfully");
    return ESP_OK;
}

/**
 * @brief Verify public key digest against eFuse secure boot digest
 */
static esp_err_t verify_pubkey_against_efuse(const uint8_t *pubkey_digest)
{
    ESP_LOGI(TAG, "Verifying public key digest against eFuse");

    /* Iterate through all eFuse key blocks */
    for (unsigned int block_id = 0; block_id < MAX_EFUSE_KEY_BLOCKS; block_id++) {

        /* For standard secure boot digest slots, check revocation */
        if (block_id < SOC_EFUSE_SECURE_BOOT_KEY_DIGESTS) {
#if SOC_EFUSE_REVOKE_BOOT_KEY_DIGESTS
            /* Check if this digest is revoked */
            bool is_revoked = esp_efuse_get_digest_revoke(block_id);
            if (is_revoked) {
                ESP_LOGI(TAG, "eFuse key digest %u is revoked, skipping", block_id);
                continue;
            }
#endif
        }

        /* Read the digest from eFuse using esp_efuse_read_block API */
        uint8_t efuse_digest[ESP_SECURE_CERT_SHA256_DIGEST_SIZE];
        esp_efuse_block_t efuse_block = EFUSE_BLK_KEY0 + block_id;

        esp_err_t ret = esp_efuse_read_block(efuse_block, efuse_digest, 0,
                                             ESP_SECURE_CERT_SHA256_DIGEST_SIZE * 8);
        if (ret != ESP_OK) {
            ESP_LOGD(TAG, "Failed to read eFuse block %d (block %u): %s",
                     efuse_block, block_id, esp_err_to_name(ret));
            continue;
        }

        /* Check if digest is empty (all zeros) */
        bool is_empty = true;
        for (int j = 0; j < ESP_SECURE_CERT_SHA256_DIGEST_SIZE; j++) {
            if (efuse_digest[j] != 0) {
                is_empty = false;
                break;
            }
        }

        if (is_empty) {
            ESP_LOGD(TAG, "eFuse block %u is empty", block_id);
            continue;
        }

        /* Compare calculated digest with eFuse digest */
        if (memcmp(pubkey_digest, efuse_digest, ESP_SECURE_CERT_SHA256_DIGEST_SIZE) == 0) {
            ESP_LOGI(TAG, "Public key digest matches eFuse block %u", block_id);
            return ESP_OK;
        } else {
            ESP_LOGD(TAG, "Public key digest does not match eFuse block %u", block_id);
        }
    }

    ESP_LOGE(TAG, "Public key digest does not match any eFuse secure boot digest");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, pubkey_digest, ESP_SECURE_CERT_SHA256_DIGEST_SIZE, ESP_LOG_ERROR);
    return ESP_FAIL;
}

#if CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME
/**
 * @brief Verify RSA signature using ROM API
 */
static esp_err_t verify_rsa_signature(const esp_secure_cert_signature_t *sig_block,
                                      const uint8_t *data_hash)
{
    ESP_LOGI(TAG, "Verifying RSA 3072 signature using ROM API");

    /* Copy RSA public key to aligned buffer to avoid packed struct warnings */
    ets_rsa_pubkey_t rsa_key;
    memcpy(&rsa_key, &sig_block->rsa_public_key, sizeof(ets_rsa_pubkey_t));

    /* Calculate public key digest for eFuse comparison
     * Based on ESP-IDF Secure Boot V2, the digest is SHA256 of the full ets_rsa_pubkey_t:
     * n[384] + e[4] + rinv[384] + mdash[4] = 776 bytes
     */
    uint8_t pubkey_digest[ESP_SECURE_CERT_SHA256_DIGEST_SIZE];
    esp_err_t ret = calculate_pubkey_digest((const uint8_t *)&rsa_key,
                                           sizeof(ets_rsa_pubkey_t),
                                           pubkey_digest);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to calculate RSA public key digest");
        return ESP_FAIL;
    }

    /* Verify public key against eFuse */
    ret = verify_pubkey_against_efuse(pubkey_digest);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "RSA public key verification against eFuse failed");
        return ESP_FAIL;
    }
    /* Verify RSA-PSS signature using ROM API */
    uint8_t verified_digest[ESP_SECURE_CERT_SHA256_DIGEST_SIZE];
    bool sig_valid = ets_rsa_pss_verify(&rsa_key,
                                        sig_block->signature,
                                        data_hash,
                                        verified_digest);

    if (!sig_valid) {
        ESP_LOGE(TAG, "RSA signature verification failed");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "RSA signature verified successfully");
    return ESP_OK;
}
#endif /* CONFIG_SECURE_BOOT_V2_RSA_ENABLED */

#if CONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME
/**
 * @brief Verify ECDSA signature using ROM API
 */
static esp_err_t verify_ecdsa_signature(const esp_secure_cert_signature_t *sig_block,
                                       const uint8_t *data_hash, uint8_t algorithm)
{
    uint8_t ecdsa_pubkey[ESP_SECURE_CERT_ECDSA256_KEY_SIZE+1];

    uint8_t signature[ESP_SECURE_CERT_ECDSA256_SIG_SIZE];
    memcpy(signature, sig_block->signature, ESP_SECURE_CERT_ECDSA256_SIG_SIZE);

    uint8_t pubkey_digest[ESP_SECURE_CERT_SHA256_DIGEST_SIZE];
    esp_err_t ret = calculate_pubkey_digest(ecdsa_pubkey, ESP_SECURE_CERT_ECDSA256_KEY_SIZE, pubkey_digest);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to calculate ECDSA public key digest");
        return ESP_FAIL;
    }

    /* Verify public key against eFuse */
    ret = verify_pubkey_against_efuse(pubkey_digest);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "ECDSA public key verification against eFuse failed");
        return ESP_FAIL;
    }
    uint8_t curve_id = ecdsa_pubkey[0];
    uint8_t pubkey_point[64];
    memcpy(pubkey_point, sig_block->ecdsa_pubkey + 1, 64);

    uint8_t verified_digest[ESP_SECURE_CERT_SHA256_DIGEST_SIZE];
    int rom_ret = ets_ecdsa_verify(pubkey_point,
                                   signature,
                                   curve_id,
                                   data_hash,
                                   verified_digest);

    if (rom_ret != 0) {
        ESP_LOGE(TAG, "ECDSA signature verification failed (ROM returned %d)", rom_ret);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "ECDSA signature verified successfully");
    return ESP_OK;
}
#endif /* CONFIG_SECURE_BOOT_V2_ECDSA_ENABLED */

/**
 * @brief Parse and verify signature block
 */
static esp_err_t verify_signature_block(const esp_secure_cert_signature_t *sig_block,
                                               const uint8_t *partition_hash)
{
    if (sig_block == NULL || partition_hash == NULL) {
        ESP_LOGE(TAG, "Invalid parameters for signature verification");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Signature block version: %d, algorithm: %d", sig_block->version, sig_block->algorithm);

#if !CONFIG_SECURE_BOOT_V2_ENABLED
    ESP_LOGW(TAG, "Secure boot V2 not enabled - skipping signature verification");
    return ESP_OK;
#else
    esp_err_t ret = ESP_FAIL;

    /* Verify based on algorithm */
    switch (sig_block->algorithm) {
        case ESP_SECURE_CERT_SIG_ALGO_RSA3072:
#if CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME
            ret = verify_rsa_signature(sig_block, partition_hash);
#else
            ESP_LOGE(TAG, "RSA signature verification not enabled (set CONFIG_SECURE_BOOT_V2_RSA_ENABLED=y)");
            ret = ESP_FAIL;
#endif
            break;

        case ESP_SECURE_CERT_SIG_ALGO_ECDSA192:
        case ESP_SECURE_CERT_SIG_ALGO_ECDSA256:
        case ESP_SECURE_CERT_SIG_ALGO_ECDSA384:
#if CONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME
            ret = verify_ecdsa_signature(sig_block, partition_hash, sig_block->algorithm);
#else
            ESP_LOGE(TAG, "ECDSA signature verification not enabled (set CONFIG_SECURE_BOOT_V2_ECDSA_ENABLED=y)");
            ret = ESP_FAIL;
#endif
            break;

        default:
            ESP_LOGE(TAG, "Unsupported signature algorithm: %d", sig_block->algorithm);
            ret = ESP_FAIL;
            break;
    }

    return ret;
#endif
}

esp_err_t esp_secure_cert_verify_partition_signature(esp_sign_verify_ctx_t *sign_verify_ctx)
{
    esp_secure_cert_partition_ctx_t *ctx = NULL;
    ESP_LOGI(TAG, "Starting custom signature verification");

    /* Map partition */
    esp_err_t ret = esp_secure_cert_map_partition(&ctx);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to map partition");
        return ESP_FAIL;
    }

    const void *partition_addr = ctx->esp_secure_cert_mapped_addr;
    if (partition_addr == NULL) {
        ESP_LOGE(TAG, "Failed to get mapped partition address");
        return ESP_FAIL;
    }

    /* Calculate partition hash (all data except signature blocks) */
    uint8_t partition_hash[ESP_SECURE_CERT_SHA256_DIGEST_SIZE];
    ret = calculate_partition_hash(partition_addr, ctx->partition->size, partition_hash);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to calculate partition hash");
        return ESP_FAIL;
    }

    /* Try to verify with each signature block */
    bool verification_passed = false;
    for (int subtype = 0; subtype < ESP_SECURE_CERT_MAX_SIGNATURE_BLOCKS; subtype++) {
        char *sig_block_data = NULL;
        uint32_t sig_block_data_len = 0;

        ret = esp_secure_cert_tlv_get_addr(ESP_SECURE_CERT_SIGNATURE_BLOCK_TLV,
                                          subtype, &sig_block_data, &sig_block_data_len);
        if (ret != ESP_OK) {
            ESP_LOGD(TAG, "No signature block found for subtype %d", subtype);
            continue;
        }

        if (sig_block_data == NULL || sig_block_data_len < sizeof(esp_secure_cert_signature_t)) {
            ESP_LOGD(TAG, "Invalid signature block %d", subtype);
            continue;
        }

        /* Parse signature block */
        esp_secure_cert_signature_t *sig_block = (esp_secure_cert_signature_t *)sig_block_data;
        ESP_LOGI(TAG, "Attempting verification with signature block %d", subtype);
        /* Verify signature */
        ret = verify_signature_block(sig_block, partition_hash);
        if (ret == ESP_OK) {
            ESP_LOGI(TAG, "Signature verification successful with block %d", subtype);
            verification_passed = true;
            break;
        } else {
            ESP_LOGW(TAG, "Signature verification failed with block %d", subtype);
        }
    }

    if (verification_passed) {
        ESP_FAULT_ASSERT(ret == ESP_OK);
        ESP_LOGI(TAG, "esp_secure_cert partition signature verification successful");
        return ESP_OK;
    }

    return ESP_FAIL;
}
