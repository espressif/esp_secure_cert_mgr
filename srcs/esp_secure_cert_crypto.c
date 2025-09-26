/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>
#include "esp_heap_caps.h"
#include "esp_err.h"
#include "esp_log.h"
#include "soc/soc_caps.h"
#include "esp_secure_cert_tlv_private.h"
#include "mbedtls/pk.h"

#if (MBEDTLS_MAJOR_VERSION < 4)
    #include "mbedtls/gcm.h"
#if __has_include("esp_idf_version.h")
    #include "esp_idf_version.h"
#endif /* __has_include("esp_idf_version.h") */
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(4, 4, 0)
    #include "esp_random.h"
#else
    #include "esp_system.h"
#endif
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
    #include "spi_flash_mmap.h"
    #include "esp_memory_utils.h"
    #include "entropy_poll.h"
#else
    #include "mbedtls/entropy_poll.h"
    #include "soc/soc_memory_layout.h"
#endif
#else
    #include "psa/crypto.h"
#endif /* (MBEDTLS_MAJOR_VERSION < 4) */

#if (MBEDTLS_VERSION_NUMBER < 0x03000000)
/* mbedtls 2.x backward compatibility */
#define MBEDTLS_2X_COMPAT 1
/**
 * Mbedtls-3.0 forward compatibility
 */
#ifndef MBEDTLS_PRIVATE
#define MBEDTLS_PRIVATE(member) member
#endif
#endif /* (MBEDTLS_VERSION_NUMBER < 0x03000000) */

#define HMAC_ENCRYPTION_IV_LEN                          (16)
static const char *TAG = "esp_secure_cert_crypto";

#if SOC_HMAC_SUPPORTED
#include "esp_hmac.h"
#define SHA256_MD_SIZE 32

int esp_pbkdf2_hmac_sha256(hmac_key_id_t hmac_key_id, const unsigned char *salt, size_t salt_len,
                           size_t iteration_count, size_t key_length, unsigned char *output)
{
    int ret = -1;
    int j;
    unsigned int i;
    unsigned char md1[SHA256_MD_SIZE] = {};
    unsigned char work[SHA256_MD_SIZE] = {};
    // Considering that we only have SHA256, fixing the MD_SIZE to 32 bytes
    const size_t MD_SIZE = SHA256_MD_SIZE;
    size_t use_len;
    unsigned char *out_p = output;
    unsigned char counter[4] = {};

    counter[3] = 1;
    uint8_t *hmac_input;
    esp_err_t esp_ret = ESP_FAIL;
    hmac_input = (uint8_t *) heap_caps_calloc(1, salt_len + sizeof(counter) + 1, MALLOC_CAP_INTERNAL);
    if (hmac_input == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for hmac input");
        return -1;
    }

    while (key_length) {
        // U1 ends up in work
        size_t hmac_input_len = 0;
        memcpy(hmac_input, salt, salt_len);
        hmac_input_len = hmac_input_len + salt_len;
        memcpy(hmac_input + salt_len, counter, sizeof(counter));
        hmac_input_len = hmac_input_len + sizeof(counter);
        esp_ret = esp_hmac_calculate(hmac_key_id, hmac_input, hmac_input_len, work);
        if (esp_ret != ESP_OK) {
            ESP_LOGE(TAG, "Could not calculate the HMAC value, returned %04X", esp_ret);
            ret = -1;
            goto cleanup;
        }

        memcpy(md1, work, MD_SIZE);

        for (i = 1; i < iteration_count; i++) {
            // U2 ends up in md1
            esp_ret = esp_hmac_calculate(hmac_key_id, md1, MD_SIZE, md1);
            if (esp_ret != ESP_OK) {
                ESP_LOGE(TAG, "Could not calculate the HMAC value, returned %04X", esp_ret);
                ret = -1;
                goto cleanup;
            }
            // U1 xor U2
            //
            for (j = 0; j < MD_SIZE; j++) {
                work[j] ^= md1[j];
            }
        }

        use_len = (key_length < MD_SIZE) ? key_length : MD_SIZE;
        memcpy(out_p, work, use_len);

        key_length -= (uint32_t) use_len;
        out_p += use_len;

        for (i = 4; i > 0; i--) {
            if (++counter[i - 1] != 0) {
                break;
            }
        }
    }
    //Success
    ret = 0;
cleanup:

    /* Zeroise buffers to clear sensitive data from memory. */
    free(hmac_input);
    memset(work, 0, SHA256_MD_SIZE);
    memset(md1, 0, SHA256_MD_SIZE);
    return ret;
}
#endif

#if (MBEDTLS_MAJOR_VERSION < 4)
#define HMAC_ENCRYPTION_RANDOM_DELAY_LIMIT 100
static esp_err_t esp_secure_cert_crypto_gcm_decrypt_internal(const uint8_t *in_buf, uint32_t len, uint8_t *output_buf, const uint8_t *key, size_t key_len,
                                const uint8_t *iv, const uint8_t *aad, const uint8_t *tag, size_t tag_len)
{
    mbedtls_gcm_context gcm_ctx;
    mbedtls_gcm_init(&gcm_ctx);
    int ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, key_len * 8);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failure at mbedtls_gcm_setkey with error code : -0x%04X", -ret);
        mbedtls_gcm_free(&gcm_ctx);
        return ESP_FAIL;
    }

    uint32_t rand_delay;
    rand_delay = esp_random() % HMAC_ENCRYPTION_RANDOM_DELAY_LIMIT;
    esp_rom_delay_us(rand_delay);

    // len = len - HMAC_ENCRYPTION_TAG_LEN;
    ret = mbedtls_gcm_auth_decrypt(&gcm_ctx, len, iv,
                                   HMAC_ENCRYPTION_IV_LEN, NULL, 0,
                                   tag,
                                   tag_len,
                                   in_buf,
                                   output_buf);

    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to decrypt the data, mbedtls_gcm_crypt_and_tag returned %02X", ret);
        mbedtls_gcm_free(&gcm_ctx);
        return ESP_FAIL;
    }

    return ESP_OK;
}
#else
static esp_err_t esp_secure_cert_crypto_gcm_decrypt_internal(const uint8_t *in_buf, uint32_t len, uint8_t *output_buf, const uint8_t *key, size_t key_len, 
                                const uint8_t *iv, const uint8_t *aad, const uint8_t *tag, size_t tag_len)
{
    int ret = ESP_FAIL;
    psa_status_t status;
    psa_aead_operation_t operation = PSA_AEAD_OPERATION_INIT;

    psa_key_id_t key_id = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_len * 8);
    status = psa_import_key(&attributes, key, key_len, &key_id);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to import the key, returned %04X", status);
        goto exit;
    }

    status = psa_aead_decrypt_setup(&operation, key_id, PSA_ALG_GCM);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to setup the operation, returned %04X", status);
        goto exit;
    }
    status = psa_aead_set_nonce(&operation, iv, HMAC_ENCRYPTION_IV_LEN);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to set the nonce, returned %04X", status);
        goto exit;
    }
    status = psa_aead_update_ad(&operation, aad, 0);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to update the ad, returned %04X", status);
        goto exit;
    }
    size_t olen = 0;
    size_t olen_tag = 0;
    status = psa_aead_update(&operation, in_buf, len, output_buf, len, &olen);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to update the data, returned %04X", status);
        goto exit;
    }
    status = psa_aead_verify(&operation, output_buf + olen, len - olen, &olen_tag, tag, tag_len);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to finish the operation, returned %d", status);
        goto exit;
    }

    ret = ESP_OK;

exit:
    psa_destroy_key(key_id);
    return ret;
}
#endif

esp_err_t esp_secure_cert_crypto_gcm_decrypt(const uint8_t *in_buf, uint32_t len, uint8_t *output_buf, const uint8_t *key,
                                size_t key_len, const uint8_t *iv, const uint8_t *aad, const uint8_t *tag, size_t tag_len)
{
    return esp_secure_cert_crypto_gcm_decrypt_internal(in_buf, len, output_buf, key, key_len, iv, aad, tag, tag_len);
}

#if (MBEDTLS_MAJOR_VERSION < 4)

static int myrand(void *rng_state, unsigned char *output, size_t len)
{
    size_t olen;
    (void) olen;
    return mbedtls_hardware_poll(rng_state, output, len, &olen);
}

static esp_err_t esp_secure_cert_convert_key_to_der_internal(const char *key_buf, size_t key_buf_len, uint8_t* output_buf, size_t output_buf_len)
{
    esp_err_t ret = ESP_FAIL;
    // Convert the private key to der
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to setup pk key, returned %04X", ret);
        goto exit;
    }

    mbedtls_ecdsa_context *key_ctx = mbedtls_pk_ec(key);
    ret = mbedtls_ecp_group_load(&key_ctx->MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to load the ecp group, returned %04X", ret);
        goto exit;
    }

    ret = mbedtls_mpi_read_binary(&key_ctx->MBEDTLS_PRIVATE(d), (const unsigned char *) key_buf, key_buf_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to read binary, returned %04X", ret);
        goto exit;
    }

    // Calculate the public key
    ret = mbedtls_ecp_mul(&key_ctx->MBEDTLS_PRIVATE(grp), &key_ctx->MBEDTLS_PRIVATE(Q), &key_ctx->MBEDTLS_PRIVATE(d), &key_ctx->MBEDTLS_PRIVATE(grp).G, myrand, NULL);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to generate public key, returned %04X", ret);
        goto exit;
    }

    // Write the private key in DER format
    int mbedtls_ret = mbedtls_pk_write_key_der(&key, output_buf, output_buf_len);
    if (mbedtls_ret != output_buf_len) {
        ESP_LOGE(TAG, "Failed to write the pem key, returned -%d", mbedtls_ret);
        goto exit;
    }
    ret = ESP_OK;

exit:
    mbedtls_pk_free(&key);
    return ret;
}
#else
static esp_err_t esp_secure_cert_convert_key_to_der_internal(const char *key_buf, size_t key_buf_len, uint8_t* output_buf, size_t output_buf_len)
{
    psa_status_t status;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, key_buf_len * 8);

    status = psa_import_key(&attributes, (unsigned char *)key_buf, key_buf_len, &key_id);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to import the key, returned %04X", status);
        goto exit;
    }
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int ret = mbedtls_pk_copy_from_psa(key_id, &key);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to copy the key, returned %04X", ret);
        goto exit;
    }
    ret = mbedtls_pk_write_key_der(&key, output_buf, output_buf_len);
    if (ret != ESP_SECURE_CERT_ECDSA_DER_KEY_SIZE) {
        ESP_LOGE(TAG, "Failed to write the pem key, returned %04X", ret);
        goto exit;
    }
    ret = ESP_OK;

exit:
    mbedtls_pk_free(&key);
    psa_destroy_key(key_id);
    return ESP_OK;
}
#endif

esp_err_t esp_secure_cert_convert_key_to_der(const char *key_buf, size_t key_buf_len, uint8_t* output_buf, size_t output_buf_len)
{
    return esp_secure_cert_convert_key_to_der_internal(key_buf, key_buf_len, output_buf, output_buf_len);
}