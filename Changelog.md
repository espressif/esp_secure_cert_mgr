# This file contains the list of changes across different versions

## v1.0.3
* esp_secure_cert API now Dynamically identify the type of partitionand access the data accordingly
* esp_secure_cert_app: Enable support for target esp32
* Added tests based on qemu
* Added priv_key functionality to the configure_esp_secure_cert.py script.
### Breaking changes in v1.0.3
* Removed all the configuration options related to selecting the type of `esp_secure_cert` partition
* Remove `esp_secure_cert_get_*_addr` API, the contents can now be obtained through `esp_secure_cert_get_*` API.
* Remove APIs to obain the contents of the DS contexts e.g. efuse key id, ciphertext, iv etc. The contents can be accesed from inside the DS context which can be obtained through respective API.
* Breaking change in the `esp_secure_cert_get_*` API:
The API now accepts `char **buffer` instead of `char *buffer`. It will allocate the required memory dynamically and directly if necessary and provide the respective pointer.
