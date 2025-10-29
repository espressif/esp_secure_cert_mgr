/*
 * SPDX-FileCopyrightText: 2022-2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ESP Secure Cert Test Application
 *
 * This test application validates the esp_secure_cert_mgr component
 * using the Unity test framework. It supports testing both TLV and
 * legacy formats across different ESP32 targets.
 *
 * Test Groups:
 * - tlv_legacy: Tests for TLV and legacy format operations
 * - crypto: Tests for cryptographic operations
 */

#include <stdio.h>
#include "unity.h"
#include "sdkconfig.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// Include Unity headers based on IDF version
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
#include "unity_test_runner.h"
#include "unity_fixture.h"
#include "unity_fixture_extras.h"
#else
// For IDF 4.x, use older Unity Fixture API
#include "unity_fixture.h"
#endif

#define TAG "app_main"

#define UNITY_FREERTOS_PRIORITY 5
#define UNITY_FREERTOS_CPU 0
#define UNITY_FREERTOS_STACK_SIZE CONFIG_UNITY_FREERTOS_STACK_SIZE

static void run_all_tests(void)
{
#if CONFIG_TEST_ESP_SECURE_CERT_TLV_LEGACY
    RUN_TEST_GROUP(tlv_legacy);
#endif
#if CONFIG_TEST_ESP_SECURE_CERT_CRYPTO
    RUN_TEST_GROUP(crypto);
#endif
}

static void test_task(void *pvParameters)
{
    vTaskDelay(2); /* Delay a bit to let the main task be deleted */

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
    // IDF 5.0+: Use UNITY_MAIN_FUNC macro
    UNITY_MAIN_FUNC(run_all_tests);
#else
    // IDF 4.x: Call Unity fixture runner directly
    const char *argv[] = {"test", "-v"};
    int argc = sizeof(argv) / sizeof(argv[0]);
    UnityMain(argc, argv, run_all_tests);
#endif

    vTaskDelete(NULL);
}

void app_main(void)
{
    xTaskCreatePinnedToCore(test_task, "testTask", UNITY_FREERTOS_STACK_SIZE, NULL, UNITY_FREERTOS_PRIORITY, NULL, UNITY_FREERTOS_CPU);
}
