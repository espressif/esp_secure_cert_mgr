/*
 * SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "esp_bit_defs.h"
#include "sdkconfig.h"
#include "soc/soc_caps.h"
#ifdef CONFIG_ESP_SECURE_CERT_DS_PERIPHERAL
#include "esp_ds.h"
#endif

/*
 * Plase note that no two TLV structures of the same type
 * can be stored in the esp_secure_cert partition at one time.
 */
typedef enum esp_secure_cert_tlv_type {
    ESP_SECURE_CERT_CA_CERT_TLV = 0,
    ESP_SECURE_CERT_DEV_CERT_TLV,
    ESP_SECURE_CERT_PRIV_KEY_TLV,
    ESP_SECURE_CERT_DS_DATA_TLV,
    ESP_SECURE_CERT_DS_CONTEXT_TLV,
    ESP_SECURE_CERT_HMAC_ECDSA_KEY_SALT,
    ESP_SECURE_CERT_TLV_SEC_CFG,
    // Any new tlv types should be added above this
    ESP_SECURE_CERT_TLV_END = 50,
    //Custom data types
    //that can be defined by the user
    ESP_SECURE_CERT_USER_DATA_1 = 51,
    ESP_SECURE_CERT_USER_DATA_2 = 52,
    ESP_SECURE_CERT_USER_DATA_3 = 53,
    ESP_SECURE_CERT_USER_DATA_4 = 54,
    ESP_SECURE_CERT_USER_DATA_5 = 54,
} esp_secure_cert_tlv_type_t;
