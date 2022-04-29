# DS Peripheral Configuration Tool
The script [configure_ds.py](./configure_ds.py) is used for configuring the DS peripheral on the ESP32-S2/ESP32-S3/ESP32-C3 SoC. The steps in the script are based on technical details of certain operations in the Digital Signature calculation, which can be found at Digital Signature Section of [ESP32-S2 TRM](https://www.espressif.com/sites/default/files/documentation/esp32-s2_technical_reference_manual_en.pdf)

The script generates a partition named `esp_secure_cert` on host machine, that contains the parameters required by the DS peripheral. The `esp_secure_cert` partition then needs to be flashed onto the device in order to use the ds peripheral.

# Configuration

1) Install the python requirements with:
```
pip install -r requirements.txt
```
2) Generate root ca and key pair:
```
openssl req -newkey rsa:2048 -nodes -keyout prvtkey.pem -x509 -days 3650 -out cacert.pem -subj "/CN=Test CA"
```

3) Generate client private key:
```
openssl genrsa -out client.key
```

4) Generate device cert:
```
openssl req -out client.csr -key client.key -new
openssl x509 -req -days 365 -in client.csr -CA cacert.pem -CAkey prvtkey.pem  -sha256 -CAcreateserial -out client.crt
```

# Generate `esp_secure_cert` partition
Following commands can be used to configure the DS peripheral and generate the `esp_secure_cert` partition.
The script can generate `cust_flash` as well as `nvs` type of `esp_secure_cert` partition. Please refer [upper level README](../README.md) for more details about type of partitions.

* When configuring the DS peripheral, by default the configuration script does not enable the read protection for the efuse key block in which the DS key is programmed. This is done for allowing flexibility while using the script for development purpose. Please provide the `--production` option as an additional argument to below command/s to enable the read protection for the respective efuse key block.

* Please remove the `--configure_ds` argument from these commands if use of the DS peripheral is disabled in the menu config. WARNING: This is not recommended for production purpose as the private key shall be stored as plaintext.

1. Generate `esp_secure_cert` partition of type `cust_flash`:

```
python configure_esp_secure_cert.py -p /* Serial port */ --keep_ds_data_on_host --efuse_key_id 1 --ca-cert cacert.pem --device-cert client.crt --private-key client.key --target_chip /* target chip */ --secure_cert_type cust_flash --configure_ds
```

2. Generate `esp_secure_cert` partition of type `nvs`:
```
python configure_esp_secure_cert.py -p /* Serial port */ --keep_ds_data_on_host --efuse_key_id 1 --ca-cert cacert.pem --device-cert client.crt --private-key client.key --target_chip /* target chip */ --secure_cert_type nvs --configure_ds
```

> The help menu for the utility can be found at `python configure_esp_secure_cert.py --help`

# Flash the `esp_secure_cert` partition
The `esp_secure_cert` partition can be flashed with help of following command:
```
esptool.py --port /* Serial port */ write_flash 0xD000 esp_ds_data/esp_secure_cert.bin
```
