/*
 * SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ESP Secure Cert App

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include <inttypes.h>
#include "esp_log.h"
#include "esp_secure_cert_read.h"
#include "esp_secure_cert_tlv_read.h"

#include "mbedtls/ssl.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "esp_idf_version.h"

#define TAG "esp_secure_cert_app"


#ifdef CONFIG_ESP_SECURE_CERT_DS_PERIPHERAL
static esp_err_t test_ciphertext_validity(esp_ds_data_ctx_t *ds_data, unsigned char *dev_cert, size_t dev_cert_len)
{
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    unsigned char *sig = NULL;

    if (ds_data == NULL || dev_cert == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    int ret = mbedtls_x509_crt_parse(&crt, dev_cert, dev_cert_len);
    if (ret < 0) {
        ESP_LOGE(TAG, "Parsing of device certificate failed, returned %02X", ret);
        goto exit;
    }

    esp_err_t esp_ret = esp_ds_init_data_ctx(ds_data);
    if (esp_ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialze the DS context");
        return esp_ret;
    }

    const size_t sig_len = 256;
    uint32_t hash[8] = {[0 ... 7] = 0xAABBCCDD};

    sig = (unsigned char *) calloc(1, 1000 * sizeof(char));
    if (sig == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for signature");
        goto exit;
    }

#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(5, 0, 0)
    ret = esp_ds_rsa_sign(NULL, NULL, NULL, 0, MBEDTLS_MD_SHA256, 0, (const unsigned char *) hash, sig);
#else
    ret = esp_ds_rsa_sign(NULL, NULL, NULL, MBEDTLS_MD_SHA256, 0, (const unsigned char *) hash, sig);
#endif
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to sign the data with rsa key, returned %02X", ret);
        goto exit;
    }
    esp_ds_release_ds_lock();

    ret = mbedtls_pk_verify(&crt.pk, MBEDTLS_MD_SHA256, (const unsigned char *) hash, 0, sig, sig_len);
    if (ret != 0) {
        printf("\nFailed to verify the data\n");
        goto exit;
    }
    free(sig);
    return ESP_OK;
exit:
    free(sig);
    mbedtls_x509_crt_free(&crt);
    printf("\nFailed to verify the ciphertext\n");
    esp_ds_release_ds_lock();
    return ESP_FAIL;
}
#else
static esp_err_t test_priv_key_validity(unsigned char* priv_key, size_t priv_key_len, unsigned char *dev_cert, size_t dev_cert_len)
{
    static const char *pers = "Hello";
    mbedtls_x509_crt crt;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk;
    unsigned char *sig = NULL;

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&crt);
    mbedtls_entropy_init(&entropy);
    mbedtls_pk_init(&pk);
    esp_err_t esp_ret = ESP_FAIL;
    if (priv_key == NULL || dev_cert == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    int ret = mbedtls_x509_crt_parse(&crt, dev_cert, dev_cert_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "Parsing of device certificate failed, returned %02X", ret);
        esp_ret = ESP_FAIL;
        goto exit;
    } else {
        ESP_LOGI(TAG, "Successfully parsed the certificate");
    }
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned -0x%04x", -ret );
        esp_ret = ESP_FAIL;
        goto exit;
    }

#if (MBEDTLS_VERSION_NUMBER < 0x03000000)
    ret = mbedtls_pk_parse_key(&pk, (const uint8_t *)priv_key, priv_key_len, NULL, 0);
#else
    ret = mbedtls_pk_parse_key(&pk, (const uint8_t *)priv_key, priv_key_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
#endif
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to parse the key");
        esp_ret = ESP_FAIL;
        goto exit;
    } else {
        ESP_LOGI(TAG, "Successfully parsed the key");
    }

    static uint32_t hash[8] = {[0 ... 7] = 0xAABBCCDD};
#define SIG_SIZE 1024
    sig = (unsigned char*)calloc(1, SIG_SIZE * sizeof(char));
    if (sig == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory");
        esp_ret = ESP_FAIL;
        goto exit;
    }
    size_t sig_len = 0;
#if (MBEDTLS_VERSION_NUMBER < 0x03000000)
    ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, (const unsigned char *) hash, 0, sig, &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);
#else
    ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, (const unsigned char *) hash, 0, sig, SIG_SIZE, &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);
#endif
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to sign the data");
        esp_ret = ESP_FAIL;
        goto exit;
    } else {
        ESP_LOGI(TAG, "Successfully signed the data");
    }

    ret = mbedtls_pk_verify(&crt.pk, MBEDTLS_MD_SHA256, (const unsigned char *) hash, 0, sig, sig_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to verify the signed data");
        esp_ret = ESP_FAIL;
        goto exit;
    }
    esp_ret = ESP_OK;
exit:
    free(sig);
    mbedtls_pk_free(&pk);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_x509_crt_free(&crt);
    return esp_ret;
}
#endif

void app_main()
{
    esp_err_t esp_ret = ESP_FAIL;

    esp_secure_cert_tlv_config_t tlv_config = {};
    esp_secure_cert_tlv_info_t tlv_info = {};

    tlv_config.type = ESP_SECURE_CERT_DEV_CERT_TLV;
    tlv_config.subtype = ESP_SECURE_CERT_SUBTYPE_0;
    esp_ret = esp_secure_cert_get_tlv_info(&tlv_config, &tlv_info);
    if (esp_ret == ESP_OK) {
        ESP_LOGI(TAG, "Device Cert: \nLength: %"PRIu32"\n%s", tlv_info.length, (char *)tlv_info.data);
    }

    tlv_config.type = ESP_SECURE_CERT_PRIV_KEY_TLV;
    tlv_config.subtype = ESP_SECURE_CERT_SUBTYPE_0;
    esp_ret = esp_secure_cert_get_tlv_info(&tlv_config, &tlv_info);
    if (esp_ret == ESP_OK) {
        ESP_LOGI(TAG, "PEM Key Length: %"PRIu32"", tlv_info.length);
    }
    esp_secure_cert_tlv_info_t dev_cert_tlv_info = {};
    tlv_config.type = ESP_SECURE_CERT_DEV_CERT_TLV;
    tlv_config.subtype = ESP_SECURE_CERT_SUBTYPE_0;
    esp_ret = esp_secure_cert_get_tlv_info(&tlv_config, &dev_cert_tlv_info);
    esp_ret = test_priv_key_validity((unsigned char *)tlv_info.data, tlv_info.length, (unsigned char *)dev_cert_tlv_info.data, dev_cert_tlv_info.length);
    if (esp_ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to validate the private key and device certificate");
    }
    if (esp_ret == ESP_OK) {
        ESP_LOGI(TAG, "Successfully obtained and verified the contents of esp_secure_cert partition");
    } else {
        ESP_LOGE(TAG, "Failed to obtain and verify the contents of the esp_secure_cert partition");
    }

    tlv_config.type = ESP_SECURE_CERT_USER_DATA_1;
    tlv_config.subtype = ESP_SECURE_CERT_SUBTYPE_0;
    esp_ret = esp_secure_cert_get_tlv_info(&tlv_config, &tlv_info);
    if (esp_ret == ESP_OK) {
        ESP_LOGI(TAG, "Custom Data 1: \nLength: %"PRIu32"\nData: '%s'", tlv_info.length, (char *)tlv_info.data);
    }

    tlv_config.subtype = ESP_SECURE_CERT_SUBTYPE_1;
    esp_ret = esp_secure_cert_get_tlv_info(&tlv_config, &tlv_info);
    if (esp_ret == ESP_OK) {
        ESP_LOGI(TAG, "Custom Data 2: \nLength: %"PRIu32"\nData: '%s'", tlv_info.length, (char *)tlv_info.data);
    }

    tlv_config.type = ESP_SECURE_CERT_USER_DATA_2;
    tlv_config.subtype = ESP_SECURE_CERT_SUBTYPE_0;
    esp_ret = esp_secure_cert_get_tlv_info(&tlv_config, &tlv_info);
    if (esp_ret == ESP_OK) {
        ESP_LOGI(TAG, "Custom Data 3: \nLength: %"PRIu32"\nData: '%s'", tlv_info.length, (char *)tlv_info.data);
    }

    tlv_config.type = ESP_SECURE_CERT_CA_CERT_TLV;
    tlv_config.subtype = ESP_SECURE_CERT_SUBTYPE_0;
    esp_ret = esp_secure_cert_get_tlv_info(&tlv_config, &tlv_info);
    if (esp_ret == ESP_OK) {
        ESP_LOGI(TAG, "CA Cert 0: \nLength: %"PRIu32"\n%s", tlv_info.length, (char *)tlv_info.data);
    }

    tlv_config.type = ESP_SECURE_CERT_CA_CERT_TLV;
    tlv_config.subtype = ESP_SECURE_CERT_SUBTYPE_1;
    esp_ret = esp_secure_cert_get_tlv_info(&tlv_config, &tlv_info);
    if (esp_ret == ESP_OK) {
        ESP_LOGI(TAG, "CA Cert 1: \nLength: %"PRIu32"\n%s", tlv_info.length, (char *)tlv_info.data);
    }

    tlv_config.type = ESP_SECURE_CERT_CA_CERT_TLV;
    tlv_config.subtype = ESP_SECURE_CERT_SUBTYPE_2;
    esp_ret = esp_secure_cert_get_tlv_info(&tlv_config, &tlv_info);
    if (esp_ret == ESP_OK) {
        ESP_LOGI(TAG, "CA Cert 2: \nLength: %"PRIu32"\n%s", tlv_info.length, (char *)tlv_info.data);
    }

    ESP_LOGI(TAG, "Printing a list of TLV entries");
    esp_secure_cert_list_tlv_entries();
}
