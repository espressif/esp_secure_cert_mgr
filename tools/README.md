# ESP Secure cert Configuration Tool
The script [configure_esp_secure_cert.py](https://github.com/espressif/esp_secure_cert_mgr/blob/feature/support_secure_cert_esp32/tools/configure_esp_secure_cert.py) is used for configuring the secure cert partition.

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
The script can generate `cust_flash` type of `esp_secure_cert` partition. Please refer [upper level README](../README.md) for more details about type of partitions.

## Generate `esp_secure_cert` partition of type `cust_flash`:

```
python configure_esp_secure_cert.py -p /* Serial port */ --ca-cert cacert.pem --device-cert client.crt --private-key client.key --target_chip /* target chip */ --secure_cert_type cust_flash
```
> Note: This step shall create the “esp_secure_cert.bin” in the “esp_secure_cert_data” directly. Its contents can be viewed by executing `hexdump esp_secure_cert_data/esp_secure_cert.bin`

# Flash the `esp_secure_cert` partition
The `esp_secure_cert` partition can be flashed with help of following command:
```
esptool.py --port /* Serial port */ write_flash 0xE000 esp_ds_data/esp_secure_cert.bin
```
> Note: the offset of the esp_secure_cert.bin is decided based on the partition_custflash.csv in the esp_secure_cert_app.
