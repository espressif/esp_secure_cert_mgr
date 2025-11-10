# This file contains the list of changes across different versions

## 2.3.6
* Fixed Python 3.7 compatibility by replacing union type operator (|) with typing.Union

## 2.3.5
* Fixed package name to comply with PEP 625 (changed from `esp-secure-cert-tool` to `esp_secure_cert_tool`)

## 2.3.4
* Fixed regression caused due to `tlv_parser` import 

## 2.3.3
* Unpinned the esptool version to avoid dependency issues 

## 2.3.2
* The `configure_esp_secure_cert.py` tool can generate the `esp_secure_cert.bin` file using an `esp_secure_cert.csv` file as input.
* The tool can also parse an existing `esp_secure_cert.bin` file to extract the partition contents and generate a corresponding CSV file, as well as output the partition data in an organized manner.
