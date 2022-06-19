# ESP Secure Certificate Application

The sample app demonstrates the use of APIs from *esp_secure_cert_mgr* to retrieve the contents of the *esp_secure_cert* partition. The example can also be used to verify the validity of the contents from the *esp_secure_cert* partition.

## Requirements
* The device must be pre-provisioned and have an *esp_secure_cert* partition.

## How to use the example
Before project configuration and build, be sure to set the correct chip target using `idf.py set-target <chip_name>`.
### Configure the project

* The *esp_secure_cert* partition needs to be generated first with help of [configure_esp_secure_cert.py](https://github.com/espressif/esp_secure_cert_mgr/blob/feature/support_secure_cert_esp32/tools/configure_esp_secure_cert.py) script. See [tools/README.md](https://github.com/espressif/esp_secure_cert_mgr/tree/feature/support_secure_cert_esp32/tools) for more details.

Select the proper *esp_secure_cert* partition type and respective *partitions_csv* file as follows:
#### 1) `esp_secure_cert` partition of type "cust_flash"
When the "esp_secure_cert" partition is of the "cust_flash" type, The data is directly stored on the flash in the tlv format. Respective APIs given in the `esp_secure_cert_mgr` component can be used to read the contents of the partition.

By default the type of *esp_secure_cert* partition is set to **cust_flash**.
Hence, No Additional configurations need to be done.

### Build and Flash

Build the project and flash it to the board, then run the monitor tool to view the serial output:

```
idf.py -p PORT flash monitor
```

(Replace PORT with the name of the serial port to use.)

(To exit the serial monitor, type ``Ctrl-]``.)

See the Getting Started Guide for full steps to configure and use ESP-IDF to build projects.

### Example Output
```
I (331) esp_secure_cert_app: Device Cert:
Length: 1233
-----BEGIN CERTIFICATE-----
.
.
-----END CERTIFICATE-----

I (441) esp_secure_cert_app: CA Cert:
Length: 1285
-----BEGIN CERTIFICATE-----
.
.
-----END CERTIFICATE-----

I (530) esp_secure_cert_app: PEM Key:
Length: 1285
-----BEGIN RSA PRIVATE KEY-----
.
.
-----END RSA PRIVATE KEY-----
```
