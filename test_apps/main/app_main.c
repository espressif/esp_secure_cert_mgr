/*
 * SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ESP Secure Cert TLV Test Application

   This test application is designed to test the TLV format support
   of esp_secure_cert_mgr component. It only outputs TLV contents
   without complex validation logic.
*/
#include "sdkconfig.h"

void esp_secure_cert_tlv_test();

extern void esp_secure_cert_crypto_test();
extern void esp_secure_cert_crypto_convert_key_to_der_test();

void app_main()
{
#ifdef CONFIG_TEST_APP_ESP_SECURE_CERT_TLV
    esp_secure_cert_tlv_test();
#endif
    esp_secure_cert_crypto_test();
    esp_secure_cert_crypto_convert_key_to_der_test();
}
