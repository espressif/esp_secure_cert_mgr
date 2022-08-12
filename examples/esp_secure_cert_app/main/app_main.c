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
#include "esp_log.h"
#include "esp_secure_cert_read.h"

#include "mbedtls/ssl.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509.h"
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

    esp_ds_init_data_ctx(ds_data);
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
    printf("\nFailed to verify the ciphertext\n");
    esp_ds_release_ds_lock();
    return ESP_FAIL;
}
#endif

void app_main()
{
    uint32_t len = 0;
    char *addr = NULL;
    esp_err_t esp_ret = ESP_FAIL;

    esp_ret = esp_secure_cert_get_device_cert(&addr, &len);
    if (esp_ret == ESP_OK) {
        ESP_LOGI(TAG, "Device Cert: \nLength: %d\n%s", strlen((char *)addr), (char *)addr);
    } else {
        ESP_LOGE(TAG, "Failed to obtain flash address of device cert");
    }

    esp_ret = esp_secure_cert_get_ca_cert(&addr, &len);
    if (esp_ret == ESP_OK) {
        ESP_LOGI(TAG, "CA Cert: \nLength: %d\n%s", strlen((char *)addr), (char *)addr);
        ESP_LOG_BUFFER_HEX_LEVEL(TAG, addr, len, ESP_LOG_DEBUG);
    } else {
        ESP_LOGE(TAG, "Failed to obtain flash address of ca_cert");
    }

#ifndef CONFIG_ESP_SECURE_CERT_DS_PERIPHERAL
    esp_ret = esp_secure_cert_get_priv_key(&addr, &len);
    if (esp_ret == ESP_OK) {
        ESP_LOGI(TAG, "PEM KEY: \nLength: %d\n%s", strlen((char *)addr), (char *)addr);
    } else {
        ESP_LOGE(TAG, "Failed to obtain flash address of private_key");
    }
#else
    esp_ds_data_ctx_t *ds_data = NULL;
    ds_data = esp_secure_cert_get_ds_ctx();
    if (ds_data != NULL) {
        ESP_LOGI(TAG, "Successfully obtained the ds context");
        ESP_LOG_BUFFER_HEX_LEVEL(TAG, ds_data->esp_ds_data->c, ESP_DS_C_LEN, ESP_LOG_DEBUG);
        ESP_LOG_BUFFER_HEX_LEVEL(TAG, ds_data->esp_ds_data->iv, ESP_DS_IV_BIT_LEN / 8, ESP_LOG_DEBUG);
        ESP_LOGI(TAG, "The value of rsa length is %d", ds_data->rsa_length_bits);
        ESP_LOGI(TAG, "The value of efuse key id is %d", ds_data->efuse_key_id);
    } else {
        ESP_LOGE(TAG, "Failed to obtain the ds context");
    }

    /* Read the dev_cert addr again */
    esp_ret = esp_secure_cert_get_device_cert(&addr, &len);
    if (esp_ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to obtain the dev cert flash address");
    }

    esp_ret = test_ciphertext_validity(ds_data, (unsigned char *)addr, len);
    if (esp_ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to validate ciphertext");
    } else {
        ESP_LOGI(TAG, "Ciphertext validated succcessfully");
    }
#endif
    if (esp_ret == ESP_OK) {
        ESP_LOGI(TAG, "Successfully obtained the contents of esp_secure_cert partition");
    } else {
        ESP_LOGE(TAG, "Failed to obtain the contents of the esp_secure_cert partition");
    }
}
