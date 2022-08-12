/*
 * SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_partition.h"
#include "esp_crc.h"
#include "esp_secure_cert_config.h"
#include "esp_secure_cert_read.h"
#include "esp_secure_cert_private.h"
#include "nvs_flash.h"

static const char *TAG = "esp_secure_cert";

#ifdef CONFIG_ESP_SECURE_CERT_NVS_PARTITION

#define NVS_STR         1
#define NVS_BLOB        2
#define NVS_U8          3
#define NVS_U16         4

static int nvs_get(const char *name_space, const char *key, char *value, size_t *len, size_t type)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open_from_partition(ESP_SECURE_CERT_NVS_PARTITION, ESP_SECURE_CERT_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Could not open NVS handle (0x%x)!", err);
        return err;
    }

    switch (type) {
    case NVS_STR:
        err = nvs_get_str(handle, key, value, len);
        break;
    case NVS_BLOB:
        err = nvs_get_blob(handle, key, value, len);
        break;
    case NVS_U8:
        err = nvs_get_u8(handle, key, (uint8_t *)value);
        break;
    case NVS_U16:
        err = nvs_get_u16(handle, key, (uint16_t *)value);
        break;
    default:
        ESP_LOGE(TAG, "Invalid type of NVS data provided");
        err = ESP_ERR_INVALID_ARG;
    }

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error (%d) reading NVS data!", err);
        return err;
    }

    nvs_close(handle);
    return err;
}

esp_err_t esp_secure_cert_get_priv_key(char *buffer, uint32_t *len)
{
    return nvs_get(ESP_SECURE_CERT_NAMESPACE, ESP_SECURE_CERT_PRIV_KEY, buffer, (size_t *)len, NVS_STR);
}

esp_err_t esp_secure_cert_get_device_cert(char *buffer, uint32_t *len)
{
    return nvs_get(ESP_SECURE_CERT_NAMESPACE, ESP_SECURE_CERT_DEV_CERT, buffer, (size_t *)len, NVS_STR);
}

esp_err_t esp_secure_cert_get_ca_cert(char *buffer, uint32_t *len)
{
    return nvs_get(ESP_SECURE_CERT_NAMESPACE, ESP_SECURE_CERT_CA_CERT, buffer, (size_t *)len, NVS_STR);
}

#ifdef CONFIG_ESP_SECURE_CERT_DS_PERIPHERAL
esp_err_t esp_secure_cert_get_ciphertext(char *buffer, uint32_t *len)
{
    return nvs_get(ESP_SECURE_CERT_NAMESPACE, ESP_SECURE_CERT_CIPHERTEXT, buffer, (size_t *)len, NVS_BLOB);
}

esp_err_t esp_secure_cert_get_iv(char *buffer, uint32_t *len)
{
    return nvs_get(ESP_SECURE_CERT_NAMESPACE, ESP_SECURE_CERT_IV, buffer, (size_t *)len, NVS_BLOB);
}

esp_err_t esp_secure_cert_get_rsa_length(uint16_t *len)
{
    return nvs_get(ESP_SECURE_CERT_NAMESPACE, ESP_SECURE_CERT_RSA_LEN, (void *)len, 0, NVS_U16);
}

esp_err_t esp_secure_cert_get_efuse_key_id(uint8_t *efuse_key_id)
{
    return nvs_get(ESP_SECURE_CERT_NAMESPACE, ESP_SECURE_CERT_EFUSE_KEY_ID, (void *)efuse_key_id, 0, NVS_U8);
}
#endif /* CONFIG_ESP_SECURE_CERT_DS_PERIPHERAL */
esp_err_t esp_secure_cert_init_nvs_partition()
{
    return nvs_flash_init_partition(ESP_SECURE_CERT_NVS_PARTITION);
}

#elif CONFIG_ESP_SECURE_CERT_CUST_FLASH_PARTITION /* CONFIG_ESP_SECURE_CERT_NVS_PARTITION */

/*
 * Map the entire esp_secure_cert partition
 * and return the virtual address.
 *
 * @note
 * The mapping is done only once and function shall
 * simply return same address in case of successive calls.
 **/
const void *esp_secure_cert_get_mapped_addr()
{
    // Once initialized, these variable shall contain valid data till reboot.
    static bool esp_secure_cert_is_mapped;
    static const void *buf;
    if (!esp_secure_cert_is_mapped) {

        esp_partition_iterator_t it = esp_partition_find(ESP_SECURE_CERT_PARTITION_TYPE,
                                      ESP_PARTITION_SUBTYPE_ANY, ESP_SECURE_CERT_PARTITION_NAME);
        if (it == NULL) {
            ESP_LOGE(TAG, "Partition not found.");
            return NULL;
        }

        const esp_partition_t *partition = esp_partition_get(it);
        if (partition == NULL) {
            ESP_LOGE(TAG, "Could not get partition.");
            return NULL;
        }

        /* Encrypted partitions need to be read via a cache mapping */
        spi_flash_mmap_handle_t handle;
        esp_err_t err;

        err = esp_partition_mmap(partition, ESP_SECURE_CERT_DATA_OFFSET, ESP_SECURE_CERT_PARTITION_SIZE, SPI_FLASH_MMAP_DATA, &buf, &handle);
        if (err != ESP_OK) {
            return NULL;
        }
        esp_secure_cert_is_mapped = true;
    }
    return buf;
}

/*
 * Find the offset of tlv structure of given type in the esp_secure_cert partition
 *
 * Note: This API also validates the crc of the respective tlv before returning the offset
 * @input
 * esp_secure_cert_addr     Memory mapped address of the esp_secure_cert partition
 * type                     Type of the tlv structure.
 *                          for calculating current crc for esp_secure_cert
 *
 * tlv_address              Void pointer to store tlv address
 *
 */
esp_err_t esp_secure_cert_find_tlv(const void *esp_secure_cert_addr, esp_secure_cert_tlv_type_t type, void **tlv_address)
{
    uint16_t tlv_offset = ESP_SECURE_CERT_DATA_OFFSET;
    while (1) {
        esp_secure_cert_tlv_header_t *tlv_header = (esp_secure_cert_tlv_header_t *)(esp_secure_cert_addr + tlv_offset);
        ESP_LOGD(TAG, "Reading from offset of %d from base of esp_secure_cert", tlv_offset);
        if (tlv_header->magic != ESP_SECURE_CERT_MAGIC) {
            if (type == ESP_SECURE_CERT_TLV_END) {
                /* The invalid magic means last tlv read successfully was the last tlv structure present,
                 * so send the end address of the tlv.
                 * This address can be used to add a new tlv structure. */
                *tlv_address = (void *) tlv_header;
                return ESP_OK;
            }
            ESP_LOGD(TAG, "Unable to find tlv of type: %d", type);
            return ESP_FAIL;
        }
        uint8_t padding_length = WORD_SIZE - (tlv_header->length % WORD_SIZE);
        padding_length = padding_length == WORD_SIZE ? 0 : padding_length;
        // crc_data_len = header_len + data_len + padding
        size_t crc_data_len = sizeof(esp_secure_cert_tlv_header_t) + tlv_header->length + padding_length;
        if (((esp_secure_cert_tlv_type_t)tlv_header->type) == type) {
            *tlv_address = (void *) tlv_header;
            uint32_t data_crc = esp_crc32_le(UINT32_MAX, (const uint8_t * )tlv_header, crc_data_len);
            esp_secure_cert_tlv_footer_t *tlv_footer = (esp_secure_cert_tlv_footer_t *)(esp_secure_cert_addr + crc_data_len + tlv_offset);
            if (tlv_footer->crc != data_crc) {
                ESP_LOGE(TAG, "Calculated crc = %08X does not match with crc"
                         "read from esp_secure_cert partition = %08X", data_crc, tlv_footer->crc);
                return ESP_FAIL;
            }
            ESP_LOGD(TAG, "tlv structure of type %d found and verified", type);
            return ESP_OK;
        } else {
            tlv_offset = tlv_offset + crc_data_len + sizeof(esp_secure_cert_tlv_footer_t);
        }
    }
}

esp_err_t esp_secure_cert_get_addr(esp_secure_cert_tlv_type_t type, const void **buffer, uint32_t *len)
{
    esp_err_t err;
    const void *esp_secure_cert_addr = esp_secure_cert_get_mapped_addr();
    if (esp_secure_cert_addr == NULL) {
        ESP_LOGE(TAG, "Error in obtaining esp_secure_cert memory mapped address");
        return ESP_FAIL;
    }
    void *tlv_address;
    err = esp_secure_cert_find_tlv(esp_secure_cert_addr, type, &tlv_address);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Could not find the tlv of type %d", type);
        return err;
    }
    esp_secure_cert_tlv_header_t *tlv_header = (esp_secure_cert_tlv_header_t *) tlv_address;
    *buffer = &tlv_header->value;
    *len = tlv_header->length;
    return ESP_OK;
}

esp_err_t esp_secure_cert_read(esp_secure_cert_tlv_type_t type, unsigned char *buffer, uint32_t *len)
{
    const void *data_buffer;
    uint32_t data_len;
    esp_err_t err;
    err = esp_secure_cert_get_addr(type, &data_buffer, &data_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read the data");
        return ESP_FAIL;
    }

    if (buffer == NULL) {
        *len = data_len;
        return ESP_OK;
    }

    if (*len < data_len) {
        ESP_LOGE(TAG, "Insufficient length of buffer. buffer size: %d, required: %d", *len, data_len);
        return ESP_FAIL;
    }

    memset(buffer, 0, *len);
    memcpy(buffer, data_buffer, data_len);
    *len = data_len;
    return ESP_OK;
}

esp_err_t esp_secure_cert_get_dev_cert_addr(const void **buffer, uint32_t *len)
{
    return esp_secure_cert_get_addr(ESP_SECURE_CERT_DEV_CERT, buffer, len);
}

esp_err_t esp_secure_cert_get_ca_cert_addr(const void **buffer, uint32_t *len)
{
    return esp_secure_cert_get_addr(ESP_SECURE_CERT_CA_CERT, buffer, len);
}

#ifndef CONFIG_ESP_SECURE_CERT_DS_PERIPHERAL
esp_err_t esp_secure_cert_get_priv_key_addr(const void **buffer, uint32_t *len)
{
    return esp_secure_cert_get_addr(ESP_SECURE_CERT_PRIV_KEY, buffer, len);
}

#endif /* !CONFIG_ESP_SECURE_CERT_DS_PEIPHERAL */
#endif /* CONFIG_ESP_SECURE_CERT_CUST_FLASH_PARTITION */

#ifdef CONFIG_ESP_SECURE_CERT_DS_PERIPHERAL
esp_ds_data_ctx_t *esp_secure_cert_get_ds_ctx()
{
    esp_err_t esp_ret;
    esp_ds_data_ctx_t *ds_data_ctx;

    ds_data_ctx = (esp_ds_data_ctx_t *)calloc(1, sizeof(esp_ds_data_ctx_t));
    if (ds_data_ctx == NULL) {
        ESP_LOGE(TAG, "Error in allocating memory for esp_ds_data_context");
        goto exit;
    }

#ifdef CONFIG_ESP_SECURE_CERT_NVS_PARTITION
    ds_data_ctx->esp_ds_data = (esp_ds_data_t *)calloc(1, sizeof(esp_ds_data_t));
    if (ds_data_ctx->esp_ds_data == NULL) {
        ESP_LOGE(TAG, "Could not allocate memory for DS data handle ");
        goto exit;
    }
    uint32_t len = ESP_DS_C_LEN;
    esp_ret = esp_secure_cert_get_ciphertext((char *)ds_data_ctx->esp_ds_data->c, &len);
    if (esp_ret != ESP_OK) {
        ESP_LOGE(TAG, "Error in reading ciphertext");
        goto exit;
    }

    len = ESP_DS_IV_LEN;
    esp_ret = esp_secure_cert_get_iv((char *)ds_data_ctx->esp_ds_data->iv, &len);
    if (esp_ret != ESP_OK) {
        ESP_LOGE(TAG, "Error in reading initialization vector");
        goto exit;
    }

    esp_ret = esp_secure_cert_get_efuse_key_id(&ds_data_ctx->efuse_key_id);
    if (esp_ret != ESP_OK) {
        ESP_LOGE(TAG, "Error in reading efuse key id");
        goto exit;
    }

    esp_ret = esp_secure_cert_get_rsa_length(&ds_data_ctx->rsa_length_bits);
    if (esp_ret != ESP_OK) {
        ESP_LOGE(TAG, "Error in reading rsa key length");
        goto exit;
    }
    ds_data_ctx->esp_ds_data->rsa_length = (ds_data_ctx->rsa_length_bits / 32) - 1;
    return ds_data_ctx;

#elif CONFIG_ESP_SECURE_CERT_CUST_FLASH_PARTITION
    uint32_t len;
    esp_ds_data_t *esp_ds_data;
    esp_ret = esp_secure_cert_get_addr(ESP_SECURE_CERT_DS_DATA, (void *) &esp_ds_data, &len);
    if (esp_ret != ESP_OK) {
        ESP_LOGE(TAG, "Error in reading ds_data, returned %04X", esp_ret);
        goto exit;
    }

    esp_ds_data_ctx_t *ds_data_ctx_flash;
    esp_ret = esp_secure_cert_get_addr(ESP_SECURE_CERT_DS_CONTEXT, (void *) &ds_data_ctx_flash, &len);
    memcpy(ds_data_ctx, ds_data_ctx_flash, len);
    ds_data_ctx->esp_ds_data = esp_ds_data;
    if (esp_ret != ESP_OK) {
        ESP_LOGE(TAG, "Error in reading ds_context, returned %04X", esp_ret);
        goto exit;
    }
    return ds_data_ctx;
#endif
exit:
    if (ds_data_ctx != NULL) {
#ifdef CONFIG_ESP_SECURE_CERT_CUST_FLASH_PARTITION
        /* In case of cust flash partition, esp_ds_data in a const pointer, thus no need to free it */
        free(ds_data_ctx->esp_ds_data);
#endif
    }
    free(ds_data_ctx);
    return NULL;
}

void esp_secure_cert_free_ds_ctx(esp_ds_data_ctx_t *ds_ctx)
{
    if (ds_ctx != NULL) {
#ifdef CONFIG_ESP_SECURE_CERT_CUST_FLASH_PARTITION
        /* In case of cust flash partition, esp_ds_data in a const pointer, thus no need to free it */
        free(ds_ctx->esp_ds_data);
#endif
    }
    free(ds_ctx);
}
#endif
