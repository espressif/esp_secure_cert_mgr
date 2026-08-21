/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Custom PSA ITS backend backed by the esp_secure_cert partition.
 *
 * This backend exposes the RSA-DS key provisioned in esp_secure_cert as a
 * pre-existing persistent PSA key — no psa_import_key() call on every boot.
 *
 * Each PSA blob is synthesised on every get() from:
 *   - the DS context read from the esp_secure_cert partition (key material,
 *     length, eFuse id), and
 *   - per-UID hardcoded PSA attributes (lifetime, type, usage, algorithm).
 *
 * Only SECURE_CERT_RSA_DS_KEY_ID is recognised here. The dispatch in get()
 * is a switch on the UID; an example wishing to expose more than one key
 * (e.g. ECDSA + RSA-DS) would add additional cases, each with its own
 * hardcoded attributes.
 */

#include <string.h>
#include <stdlib.h>

#include "secure_cert_its_backend.h"
#include "esp_secure_cert_read.h"
#include "esp_log.h"

#include "esp_psa_its.h"
#include "esp_psa_key_file.h"
#include "psa_crypto_driver_esp_rsa_ds.h"

static const char *TAG = "secure_cert_its";

/* ---- Per-key-type attribute decisions, keyed on UID ---- */
static psa_status_t synthesise_rsa_ds_blob(uint32_t data_offset, uint32_t data_length,
                                           void *p_data, size_t *p_data_length)
{
    esp_ds_data_ctx_t *ds_ctx = esp_secure_cert_get_ds_ctx();
    if (ds_ctx == NULL || ds_ctx->esp_ds_data == NULL) {
        ESP_LOGE(TAG, "Failed to read DS context from esp_secure_cert");
        return PSA_ERROR_DOES_NOT_EXIST;
    }
    esp_rsa_ds_opaque_key_t opaque_key = { .ds_data_ctx = ds_ctx };

    size_t key_data_size = esp_rsa_ds_persistent_key_buffer_size(&opaque_key);
    uint8_t *key_data = calloc(1, key_data_size);
    if (key_data == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    size_t key_data_len = 0;
    psa_status_t status = esp_rsa_ds_format_persistent_key_buffer(
        &opaque_key, key_data, key_data_size, &key_data_len);
    if (status != PSA_SUCCESS) {
        free(key_data);
        return status;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_ESP_RSA_DS);
    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attr, ds_ctx->rsa_length_bits);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));

    size_t blob_size = esp_psa_key_file_size(key_data_len);
    if (data_offset + data_length > blob_size) {
        free(key_data);
        psa_reset_key_attributes(&attr);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t *blob = calloc(1, blob_size);
    if (blob == NULL) {
        free(key_data);
        psa_reset_key_attributes(&attr);
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    size_t written = 0;
    status = esp_psa_key_file_pack(&attr, key_data, key_data_len,
                                   blob, blob_size, &written);
    if (status != PSA_SUCCESS) {
        free(blob);
        free(key_data);
        psa_reset_key_attributes(&attr);
        return status;
    }

    if (data_length > 0 && p_data != NULL) {
        memcpy(p_data, blob + data_offset, data_length);
    }
    if (p_data_length != NULL) {
        *p_data_length = data_length;
    }

    free(blob);
    free(key_data);
    psa_reset_key_attributes(&attr);
    return PSA_SUCCESS;
}

static psa_status_t rsa_ds_blob_info(struct psa_storage_info_t *p_info)
{
    esp_ds_data_ctx_t *ds_ctx = esp_secure_cert_get_ds_ctx();
    if (ds_ctx == NULL) {
        return PSA_ERROR_DOES_NOT_EXIST;
    }
    esp_rsa_ds_opaque_key_t opaque_key = { .ds_data_ctx = ds_ctx };

    p_info->size  = (uint32_t)esp_psa_key_file_size(
        esp_rsa_ds_persistent_key_buffer_size(&opaque_key));
    p_info->flags = PSA_STORAGE_FLAG_NONE;
    return PSA_SUCCESS;
}

/* ---- Custom ITS callbacks ---- */

static psa_status_t secure_cert_its_set(void *ctx, psa_storage_uid_t uid,
                                        uint32_t data_length, const void *p_data,
                                        psa_storage_create_flags_t create_flags)
{
    /* The keys this backend serves are eFuse-bound and require host-side
     * provisioning, which PSA Crypto's runtime set() cannot perform.
     * A backend exposing app-writable keys through this UID range could
     * dispatch on uid here and route writes to esp_secure_cert_append_tlv(). */
    (void)ctx;
    (void)uid;
    (void)data_length;
    (void)p_data;
    (void)create_flags;
    return PSA_ERROR_NOT_PERMITTED;
}

static psa_status_t secure_cert_its_get(void *ctx, psa_storage_uid_t uid,
                                        uint32_t data_offset, uint32_t data_length,
                                        void *p_data, size_t *p_data_length)
{
    (void)ctx;
    switch (uid) {
    case SECURE_CERT_RSA_DS_KEY_ID:
        return synthesise_rsa_ds_blob(data_offset, data_length, p_data, p_data_length);
    default:
        return PSA_ERROR_DOES_NOT_EXIST;
    }
}

static psa_status_t secure_cert_its_get_info(void *ctx, psa_storage_uid_t uid,
                                             struct psa_storage_info_t *p_info)
{
    (void)ctx;
    switch (uid) {
    case SECURE_CERT_RSA_DS_KEY_ID:
        return rsa_ds_blob_info(p_info);
    default:
        return PSA_ERROR_DOES_NOT_EXIST;
    }
}

static psa_status_t secure_cert_its_remove(void *ctx, psa_storage_uid_t uid)
{
    /* Symmetric with set(): the eFuse-backed keys this backend serves
     * cannot be removed at runtime. A backend serving app-writable keys
     * would dispatch on uid here and call esp_secure_cert's TLV erase
     * APIs for those UIDs. */
    (void)ctx;
    (void)uid;
    return PSA_ERROR_NOT_PERMITTED;
}

/* ---- Registration ---- */

esp_err_t secure_cert_its_backend_register(void)
{
    static const esp_psa_its_custom_ops_t ops = {
        .set      = secure_cert_its_set,
        .get      = secure_cert_its_get,
        .get_info = secure_cert_its_get_info,
        .remove   = secure_cert_its_remove,
        .ctx      = NULL,
    };

    psa_status_t status = esp_psa_its_register_custom_backend(&ops);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to register custom backend: %d", (int)status);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "esp_secure_cert ITS backend registered (RSA-DS key 0x%lx)",
             (unsigned long)SECURE_CERT_RSA_DS_KEY_ID);
    return ESP_OK;
}
