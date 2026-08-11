#!/usr/bin/env python
# SPDX-FileCopyrightText: 2020-2024 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import base64
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest


class ConfigureEspSecureCertTest(unittest.TestCase):
    """Test class for configure_esp_secure_cert.py script functionality"""

    def setUp(self):
        """Set up test environment before each test"""
        # Get the directory paths
        self.test_dir = os.path.dirname(os.path.abspath(__file__))
        self.tools_dir = os.path.dirname(self.test_dir)
        self.script_path = os.path.join(self.tools_dir, 'configure_esp_secure_cert.py')
        self.input_data_dir = os.path.join(self.test_dir, 'input_data')

        # Input files
        self.csv_file = os.path.join(self.input_data_dir, 'esp_secure_cert_config_examples.csv')
        self.expected_bin = os.path.join(self.input_data_dir, 'esp_secure_cert.bin')

        # Create a temporary working directory
        self.temp_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.temp_dir)

        # Copy required certificate files to temp directory
        # The script expects these files to be in the current working directory
        cert_files = ['cacert.pem', 'client.crt', 'client.key']
        for cert_file in cert_files:
            src_path = os.path.join(self.input_data_dir, cert_file)
            dst_path = os.path.join(self.temp_dir, cert_file)
            if os.path.exists(src_path):
                shutil.copy2(src_path, dst_path)

        # Expected output directory and file
        self.output_dir = os.path.join(self.temp_dir, 'esp_secure_cert_data')
        self.generated_bin = os.path.join(self.output_dir, 'esp_secure_cert.bin')

        # Verify required files exist
        self.assertTrue(
            os.path.exists(self.script_path),
            f"Script not found: {self.script_path}")
        self.assertTrue(
            os.path.exists(self.csv_file),
            f"CSV file not found: {self.csv_file}")
        self.assertTrue(
            os.path.exists(self.expected_bin),
            f"Expected binary not found: {self.expected_bin}")

    def tearDown(self):
        """Clean up after each test"""
        os.chdir(self.original_cwd)
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _calculate_sha256(self, file_path):
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def _run_configure_script(self, args):
        """Run the configure_esp_secure_cert.py script with given arguments"""
        cmd = [sys.executable, self.script_path] + args
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result

    def test_generate_esp_secure_cert_bin_from_csv(self):
        """Test generating esp_secure_cert.bin from CSV configuration"""
        # Run the script with CSV input
        args = [
            '--esp_secure_cert_csv', self.csv_file,
            '--target_chip', 'esp32c3',
            '--skip_flash'  # Skip flashing to avoid hardware dependency
        ]

        result = self._run_configure_script(args)

        # Check if script executed successfully
        self.assertEqual(
            result.returncode, 0,
            f"Script failed with stderr: {result.stderr}\n"
            f"stdout: {result.stdout}")

        # Verify output directory was created
        self.assertTrue(
            os.path.exists(self.output_dir),
            f"Output directory not created: {self.output_dir}")

        # Verify binary file was generated
        self.assertTrue(
            os.path.exists(self.generated_bin),
            f"Generated binary not found: {self.generated_bin}")

        # Calculate SHA256 hashes
        generated_hash = self._calculate_sha256(self.generated_bin)
        expected_hash = self._calculate_sha256(self.expected_bin)

        # Compare hashes
        self.assertEqual(
            generated_hash, expected_hash,
            f"SHA256 mismatch:\n"
            f"Generated: {generated_hash}\n"
            f"Expected:  {expected_hash}\n"
            f"Generated file: {self.generated_bin}\n"
            f"Expected file: {self.expected_bin}")

    def test_script_help_option(self):
        """Test that the script shows help when --help is provided"""
        result = self._run_configure_script(['--help'])

        # Help should exit with code 0
        self.assertEqual(result.returncode, 0)

        # Help output should contain usage information
        self.assertIn('usage:', result.stdout.lower())
        self.assertIn('esp_secure_cert', result.stdout.lower())

    def test_script_missing_csv_file(self):
        """Test script behavior with missing CSV file"""
        non_existent_csv = os.path.join(self.temp_dir, 'non_existent.csv')

        args = [
            '--esp_secure_cert_csv', non_existent_csv,
            '--target_chip', 'esp32c3',
            '--skip_flash'
        ]

        result = self._run_configure_script(args)

        # Script should fail with non-zero exit code
        self.assertNotEqual(result.returncode, 0)

    def test_generated_files_structure(self):
        """Test that all expected files are generated in the output
        directory"""
        args = [
            '--esp_secure_cert_csv', self.csv_file,
            '--target_chip', 'esp32c3',
            '--skip_flash'
        ]

        result = self._run_configure_script(args)
        self.assertEqual(
            result.returncode, 0, f"Script failed: {result.stderr}")

        # Check that the binary file exists and has reasonable size
        self.assertTrue(os.path.exists(self.generated_bin))

        # Binary should not be empty
        bin_size = os.path.getsize(self.generated_bin)
        self.assertGreater(bin_size, 0, "Generated binary file is empty")

    def test_custom_data_from_file(self):
        """Test adding custom data from a file to esp_secure_cert.bin"""
        # Create a test custom data file
        custom_data_file = os.path.join(self.temp_dir, 'custom_data.txt')
        custom_data_content = b"Custom device configuration data"
        with open(custom_data_file, 'wb') as f:
            f.write(custom_data_content)

        # Create a CSV with custom data entry
        csv_content = (
            "tlv_type,tlv_subtype,data_value,data_type,priv_key_type,"
            "algorithm,key_size,efuse_id,efuse_key\n"
            "ESP_SECURE_CERT_CA_CERT_TLV,0,cacert.pem,file,,,,,\n"
            "ESP_SECURE_CERT_DEV_CERT_TLV,0,client.crt,file,,,,,\n"
            "ESP_SECURE_CERT_PRIV_KEY_TLV,0,client.key,file,plaintext,"
            "RSA,,,\n"
            "ESP_SECURE_CERT_USER_DATA_3_TLV,0,custom_data.txt,file,,,,,\n"
        )

        csv_file = os.path.join(self.temp_dir, 'test_custom_data.csv')
        with open(csv_file, 'w') as f:
            f.write(csv_content)

        # Run the script
        args = [
            '--esp_secure_cert_csv', csv_file,
            '--target_chip', 'esp32c3',
            '--skip_flash'
        ]
        result = self._run_configure_script(args)

        # Check if script executed successfully
        self.assertEqual(
            result.returncode, 0,
            f"Script failed: {result.stderr}")

        # Verify binary was generated
        generated_bin = os.path.join(
            self.temp_dir, 'esp_secure_cert_data', 'esp_secure_cert.bin')
        self.assertTrue(
            os.path.exists(generated_bin),
            "Binary file not generated")

        # Parse the binary to verify custom data was added
        parse_result = self._run_configure_script(
            ['--parse_bin', generated_bin])
        self.assertEqual(
            parse_result.returncode, 0,
            f"Parse failed: {parse_result.stderr}")

        # Check that custom data appears in parsed output
        self.assertIn(
            'ESP_SECURE_CERT_USER_DATA_3_TLV', parse_result.stdout,
            "Custom data TLV not found in parsed output")

        # Verify the parsed CSV contains the custom data entry
        parsed_csv = os.path.join(
            self.temp_dir, 'esp_secure_cert_parsed_data',
            'esp_secure_cert_parsed.csv')
        self.assertTrue(
            os.path.exists(parsed_csv),
            "Parsed CSV not generated")

        with open(parsed_csv, 'r') as f:
            parsed_content = f.read()

        self.assertIn(
            'ESP_SECURE_CERT_USER_DATA_3_TLV', parsed_content,
            "Custom data not found in parsed CSV")


class ConfigureEspSecureCertIntegrationTest(unittest.TestCase):
    """Integration tests for configure_esp_secure_cert.py with different
    configurations"""

    def setUp(self):
        """Set up test environment"""
        self.test_dir = os.path.dirname(os.path.abspath(__file__))
        self.tools_dir = os.path.dirname(self.test_dir)
        self.script_path = os.path.join(
            self.tools_dir, 'configure_esp_secure_cert.py')
        self.input_data_dir = os.path.join(self.test_dir, 'input_data')

        # Create temporary directory
        self.temp_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.temp_dir)

        # Copy required certificate files to temp directory
        # The script expects these files to be in the current working directory
        cert_files = ['cacert.pem', 'client.crt', 'client.key']
        for cert_file in cert_files:
            src_path = os.path.join(self.input_data_dir, cert_file)
            dst_path = os.path.join(self.temp_dir, cert_file)
            if os.path.exists(src_path):
                shutil.copy2(src_path, dst_path)

    def tearDown(self):
        """Clean up after test"""
        os.chdir(self.original_cwd)
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_different_target_chips(self):
        """Test script with different target chip configurations"""
        csv_file = os.path.join(
            self.test_dir, 'input_data',
            'esp_secure_cert_config_examples.csv')

        # Test with different target chips
        target_chips = ['esp32', 'esp32s3']

        for chip in target_chips:
            with self.subTest(chip=chip):
                # Clean up previous run
                output_dir = os.path.join(
                    self.temp_dir, 'esp_secure_cert_data')
                if os.path.exists(output_dir):
                    shutil.rmtree(output_dir)

                args = [
                    '--esp_secure_cert_csv', csv_file,
                    '--target_chip', chip,
                    '--skip_flash'
                ]

                result = subprocess.run(
                    [sys.executable, self.script_path] + args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                self.assertEqual(
                    result.returncode, 0,
                    f"Script failed for {chip}: {result.stderr}")

                # Verify binary was generated
                generated_bin = os.path.join(
                    output_dir, 'esp_secure_cert.bin')
                self.assertTrue(
                    os.path.exists(generated_bin),
                    f"Binary not generated for {chip}")


class TempFileCollisionTest(unittest.TestCase):
    """Regression tests for the temporary file name collision (issue #32).

    Entries whose data is supplied inline (string/hex/base64) are staged to a
    temporary file during CSV parsing and only read back when the partition is
    built. The temporary name used to be derived from
    ``hash(data_value) % 10000``, so two entries with different content could
    share a name; the second write silently destroyed the first entry's data and
    the tool still exited 0.
    """

    CSV_FIELDS = ('tlv_type,tlv_subtype,data_value,data_type,'
                  'priv_key_type,algorithm,key_size,efuse_id,efuse_key')

    def setUp(self):
        self.test_dir = os.path.dirname(os.path.abspath(__file__))
        self.tools_dir = os.path.dirname(self.test_dir)
        self.script_path = os.path.join(
            self.tools_dir, 'configure_esp_secure_cert.py')
        self.input_data_dir = os.path.join(self.test_dir, 'input_data')
        self.temp_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.temp_dir)

    def tearDown(self):
        os.chdir(self.original_cwd)
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _cert_b64(self, filename):
        path = os.path.join(self.input_data_dir, filename)
        with open(path, 'rb') as f:
            return base64.b64encode(f.read()).decode()

    def _write_csv(self, name, rows):
        path = os.path.join(self.temp_dir, name)
        with open(path, 'w') as f:
            f.write(self.CSV_FIELDS + '\n')
            for tlv_type, subtype, value, data_type in rows:
                f.write(f'{tlv_type},{subtype},{value},{data_type},,,,,\n')
        return path

    def _run_tool(self, csv_path):
        return subprocess.run(
            [sys.executable, self.script_path,
             '--target_chip', 'esp32c3',
             '--secure_cert_type', 'cust_flash_tlv',
             '--esp_secure_cert_csv', csv_path,
             '--skip_flash'],
            capture_output=True, text=True, cwd=self.temp_dir)

    def _new_esp_secure_cert(self):
        sys.path.insert(0, self.tools_dir)
        from esp_secure_cert.tlv_format_construct import EspSecureCert
        return EspSecureCert()

    def test_distinct_content_gets_distinct_temp_files(self):
        """Different content must never share a staging file."""
        esc = self._new_esp_secure_cert()
        paths = {esc._parse_data_from_any_format(v, 'hex', True)
                 for v in ('00112233', 'aabbccdd', 'deadbeef')}
        self.assertEqual(
            len(paths), 3,
            'entries with different content shared a temporary file')

    def test_temp_file_name_is_full_content_digest(self):
        """Pin the naming scheme: full SHA256 of the decoded content."""
        esc = self._new_esp_secure_cert()
        path = esc._parse_data_from_any_format('00112233', 'hex', True)
        expected = hashlib.sha256(bytes.fromhex('00112233')).hexdigest()
        self.assertEqual(os.path.basename(path), f'temp_key_{expected}.key')
        self.assertTrue(os.path.basename(path).startswith('temp_'),
                        'name must keep the temp_ prefix so cleanup removes it')

    def test_identical_content_shares_one_temp_file(self):
        """Identical content is de-duplicated, which is safe and intended."""
        esc = self._new_esp_secure_cert()
        paths = {esc._parse_data_from_any_format('00112233', 'hex', True)
                 for _ in range(3)}
        self.assertEqual(len(paths), 1)

    def test_same_content_under_distinct_ids_is_not_a_duplicate(self):
        """Uniqueness is decided by (tlv_type, tlv_subtype) only.

        The same certificate stored under different type/subtype pairs is three
        distinct entries and all three must reach the partition, even though
        they share one content-addressed staging file.
        """
        cert = self._cert_b64('cacert.pem')
        csv_path = self._write_csv('same_content.csv', [
            ('ESP_SECURE_CERT_DEV_CERT_TLV', 0, cert, 'base64'),
            ('ESP_SECURE_CERT_CA_CERT_TLV', 0, cert, 'base64'),
            ('ESP_SECURE_CERT_CA_CERT_TLV', 1, cert, 'base64'),
        ])
        result = self._run_tool(csv_path)
        self.assertEqual(result.returncode, 0,
                         f'tool failed: {result.stdout}\n{result.stderr}')
        self.assertIn('Successfully processed 3 out of 3 entries',
                      result.stdout)
        for tlv_type, subtype in ((1, 0), (0, 0), (0, 1)):
            self.assertIn(f'Added TLV entry: type={tlv_type}, '
                          f'subtype={subtype}', result.stdout)

    def test_duplicate_type_and_subtype_is_rejected(self):
        """A real duplicate (same type AND subtype) must abort, not warn."""
        csv_path = self._write_csv('duplicate.csv', [
            ('ESP_SECURE_CERT_DEV_CERT_TLV', 0,
             self._cert_b64('client.crt'), 'base64'),
            ('ESP_SECURE_CERT_DEV_CERT_TLV', 0,
             self._cert_b64('cacert.pem'), 'base64'),
        ])
        result = self._run_tool(csv_path)
        self.assertNotEqual(result.returncode, 0,
                            'duplicate entry must not exit successfully')
        self.assertFalse(
            os.path.exists(os.path.join(
                self.temp_dir, 'esp_secure_cert_data', 'esp_secure_cert.bin')),
            'no partition may be written when an entry is rejected')

    def test_duplicate_error_does_not_leak_data_value(self):
        """The duplicate report must not echo entry data (key material)."""
        secret = self._cert_b64('client.crt')
        csv_path = self._write_csv('duplicate_leak.csv', [
            ('ESP_SECURE_CERT_DEV_CERT_TLV', 0, secret, 'base64'),
            ('ESP_SECURE_CERT_DEV_CERT_TLV', 0, secret, 'base64'),
        ])
        result = self._run_tool(csv_path)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_unprocessable_entry_aborts_without_partition(self):
        """A dropped entry must fail the run instead of exiting 0."""
        csv_path = self._write_csv('bad_entry.csv', [
            ('ESP_SECURE_CERT_DEV_CERT_TLV', 0,
             self._cert_b64('client.crt'), 'base64'),
            ('ESP_SECURE_CERT_CA_CERT_TLV', 0,
             '/nonexistent/does_not_exist.pem', 'file'),
        ])
        result = self._run_tool(csv_path)
        self.assertNotEqual(result.returncode, 0,
                            'a skipped entry must not exit successfully')
        self.assertFalse(
            os.path.exists(os.path.join(
                self.temp_dir, 'esp_secure_cert_data', 'esp_secure_cert.bin')),
            'an incomplete partition must never be written')


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
