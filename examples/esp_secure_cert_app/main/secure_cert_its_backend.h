/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Custom PSA ITS backend that exposes the RSA-DS key provisioned in the
 * esp_secure_cert partition as a pre-existing persistent PSA key.
 */

#pragma once

#include "esp_err.h"
#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief UID under which the esp_secure_cert RSA-DS key is exposed.
 *
 * Must fall within CONFIG_MBEDTLS_PSA_ITS_CUSTOM_BACKEND_UID_MIN..MAX.
 */
#define SECURE_CERT_RSA_DS_KEY_ID  ((psa_key_id_t) 0x30000001)

/**
 * @brief Register this example's custom PSA ITS backend with the framework.
 *
 * Once registered, PSA Crypto operations using SECURE_CERT_RSA_DS_KEY_ID
 * will be routed to this backend, which materialises the RSA-DS key
 * from esp_secure_cert on demand.
 *
 * @return ESP_OK on success
 * @return ESP_FAIL if registration fails (see logs)
 */
esp_err_t secure_cert_its_backend_register(void);

#ifdef __cplusplus
}
#endif
