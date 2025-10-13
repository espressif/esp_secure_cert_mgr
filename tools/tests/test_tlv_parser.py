#!/usr/bin/env python
# SPDX-FileCopyrightText: 2020-2024 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest


class TlvParserTest(unittest.TestCase):
    """Test class for TLV parser functionality in configure_esp_secure_cert.py"""
    
    def setUp(self):
        """Set up test environment before each test"""
        # Get the directory paths
        self.test_dir = os.path.dirname(os.path.abspath(__file__))
        self.tools_dir = os.path.dirname(self.test_dir)
        self.script_path = os.path.join(self.tools_dir, 'configure_esp_secure_cert.py')
        self.input_data_dir = os.path.join(self.test_dir, 'input_data')
        
        # Input files
        self.bin_file = os.path.join(self.input_data_dir, 'esp_secure_cert.bin')
        self.expected_parsed_dir = os.path.join(self.input_data_dir, 'esp_secure_cert_parsed_data_expected')
        
        # Create a temporary working directory
        self.temp_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.temp_dir)
        
        # Copy the binary file to temp directory for parsing
        self.temp_bin_file = os.path.join(self.temp_dir, 'esp_secure_cert.bin')
        shutil.copy2(self.bin_file, self.temp_bin_file)
        
        # Expected output directory and files
        self.output_dir = os.path.join(self.temp_dir, 'esp_secure_cert_parsed_data')
        
        # Verify required files exist
        self.assertTrue(os.path.exists(self.script_path), 
                       f"Script not found: {self.script_path}")
        self.assertTrue(os.path.exists(self.bin_file), 
                       f"Binary file not found: {self.bin_file}")
        self.assertTrue(os.path.exists(self.expected_parsed_dir), 
                       f"Expected parsed directory not found: {self.expected_parsed_dir}")
    
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
    
    def test_parse_esp_secure_cert_bin(self):
        """Test parsing esp_secure_cert.bin and comparing generated files with expected"""
        # Run the script with --parse_bin option
        args = ['--parse_bin', 'esp_secure_cert.bin']
        result = self._run_configure_script(args)
        
        # Check if script executed successfully
        self.assertEqual(result.returncode, 0, 
                        f"Parse script failed with stderr: {result.stderr}\nstdout: {result.stdout}")
        
        # Verify output directory was created
        self.assertTrue(os.path.exists(self.output_dir), 
                       f"Parsed output directory not created: {self.output_dir}")
        
        # Get list of expected files
        expected_files = []
        if os.path.exists(self.expected_parsed_dir):
            for root, dirs, files in os.walk(self.expected_parsed_dir):
                for file in files:
                    rel_path = os.path.relpath(os.path.join(root, file), self.expected_parsed_dir)
                    expected_files.append(rel_path)
        
        # Verify all expected files were generated
        for expected_file in expected_files:
            generated_file_path = os.path.join(self.output_dir, expected_file)
            self.assertTrue(os.path.exists(generated_file_path), 
                           f"Expected parsed file not generated: {expected_file}")
            
            # Compare SHA256 hashes
            expected_file_path = os.path.join(self.expected_parsed_dir, expected_file)
            generated_hash = self._calculate_sha256(generated_file_path)
            expected_hash = self._calculate_sha256(expected_file_path)
            
            self.assertEqual(generated_hash, expected_hash,
                            f"SHA256 mismatch for {expected_file}:\n"
                            f"Generated: {generated_hash}\n"
                            f"Expected:  {expected_hash}\n"
                            f"Generated file: {generated_file_path}\n"
                            f"Expected file: {expected_file_path}")
        
        # Verify that no unexpected files were generated
        generated_files = []
        for root, dirs, files in os.walk(self.output_dir):
            for file in files:
                rel_path = os.path.relpath(os.path.join(root, file), self.output_dir)
                generated_files.append(rel_path)
        
        unexpected_files = set(generated_files) - set(expected_files)
        self.assertEqual(len(unexpected_files), 0, 
                        f"Unexpected files generated: {unexpected_files}")
    
    def test_parse_bin_help_option(self):
        """Test that the script shows help when --help is provided"""
        result = self._run_configure_script(['--help'])
        
        # Help should exit with code 0
        self.assertEqual(result.returncode, 0)
        
        # Help output should contain usage information
        self.assertIn('usage:', result.stdout.lower())
        self.assertIn('parse_bin', result.stdout.lower())
    
    def test_parse_bin_missing_file(self):
        """Test script behavior with missing binary file"""
        non_existent_bin = os.path.join(self.temp_dir, 'non_existent.bin')
        
        args = ['--parse_bin', non_existent_bin]
        result = self._run_configure_script(args)
        
        # Script should fail with non-zero exit code
        self.assertNotEqual(result.returncode, 0)
        
        # Should contain error message about missing file
        self.assertIn('does not exist', result.stdout)
    
    def test_parse_bin_invalid_file_extension(self):
        """Test script behavior with invalid file extension"""
        # Create a dummy file with wrong extension
        invalid_file = os.path.join(self.temp_dir, 'test.txt')
        with open(invalid_file, 'w') as f:
            f.write('dummy content')
        
        args = ['--parse_bin', invalid_file]
        result = self._run_configure_script(args)
        
        # Script should fail with non-zero exit code
        self.assertNotEqual(result.returncode, 0)
        
        # Should contain error message about invalid extension
        self.assertIn('not a .bin file', result.stdout)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
