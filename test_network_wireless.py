#!/usr/bin/env python3
"""
Unit tests for mod_network_wireless.py
Tests: Logger, ScopeValidator, data models, basic attack structures

Run: python3 -m pytest test_network_wireless.py -v
Or:  python3 test_network_wireless.py
"""

import unittest
import tempfile
import os
from pathlib import Path
from datetime import datetime

# Import module under test
MODULE_AVAILABLE = True
IMPORT_ERROR = ""
try:
    from mod_network_wireless import (
        Logger, ScopeValidator, AuthorizationError,
        NetworkHost, CapturedCredential, WirelessNetwork,
        Layer2Attacks, CredentialCapture, KerberosAttacks,
        WirelessAttacks, NetworkRecon, AttackChains
    )
except ImportError as e:
    MODULE_AVAILABLE = False
    IMPORT_ERROR = str(e)


class TestLogger(unittest.TestCase):
    """Test logging functionality"""

    def setUp(self):
        """Create temporary log file"""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = Path(self.temp_dir) / "test.log"

    def tearDown(self):
        """Clean up"""
        if self.log_file.exists():
            self.log_file.unlink()
        os.rmdir(self.temp_dir)

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_logger_creation(self):
        """Test logger initialization"""
        logger = Logger(str(self.log_file))
        self.assertIsNotNone(logger)
        self.assertEqual(logger.log_file, self.log_file)

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_log_attack(self):
        """Test attack logging"""
        logger = Logger(str(self.log_file))
        logger.log_attack("test_attack", "192.168.1.1", "test_method", "success")

        # Check log file was created
        self.assertTrue(self.log_file.exists())

        # Check log content
        content = self.log_file.read_text()
        self.assertIn("test_attack", content)
        self.assertIn("192.168.1.1", content)

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_log_credential(self):
        """Test credential logging"""
        logger = Logger(str(self.log_file))
        logger.log_credential("ntlm_hash", "user123:password", "llmnr_poison")

        content = self.log_file.read_text()
        self.assertIn("CREDENTIAL_CAPTURED", content)
        self.assertIn("llmnr_poison", content)


class TestScopeValidator(unittest.TestCase):
    """Test authorization and scope validation"""

    def setUp(self):
        """Create temporary scope file"""
        self.temp_dir = tempfile.mkdtemp()
        self.scope_file = Path(self.temp_dir) / "scope.txt"

    def tearDown(self):
        """Clean up"""
        if self.scope_file.exists():
            self.scope_file.unlink()
        os.rmdir(self.temp_dir)

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_scope_validator_creation(self):
        """Test scope validator initialization"""
        validator = ScopeValidator(str(self.scope_file))
        self.assertIsNotNone(validator)

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_scope_exact_match(self):
        """Test exact IP in scope"""
        self.scope_file.write_text("192.168.1.100\n")
        validator = ScopeValidator(str(self.scope_file))

        self.assertTrue(validator.is_in_scope("192.168.1.100"))
        self.assertFalse(validator.is_in_scope("192.168.1.101"))

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_scope_cidr_matching(self):
        """Test CIDR range matching"""
        self.scope_file.write_text("192.168.1.0/24\n")
        validator = ScopeValidator(str(self.scope_file))

        self.assertTrue(validator.is_in_scope("192.168.1.50"))
        self.assertTrue(validator.is_in_scope("192.168.1.1"))
        self.assertTrue(validator.is_in_scope("192.168.1.254"))
        self.assertFalse(validator.is_in_scope("192.168.2.1"))

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_scope_out_of_scope(self):
        """Test out-of-scope targets"""
        self.scope_file.write_text("192.168.1.0/24\n-192.168.1.50\n")
        validator = ScopeValidator(str(self.scope_file))

        # 192.168.1.50 is explicitly out-of-scope
        self.assertFalse(validator.is_in_scope("192.168.1.50"))
        # But other IPs in range are in scope
        self.assertTrue(validator.is_in_scope("192.168.1.100"))


class TestDataModels(unittest.TestCase):
    """Test data structure models"""

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_network_host(self):
        """Test NetworkHost data model"""
        host = NetworkHost(
            ip="192.168.1.100",
            mac="aa:bb:cc:dd:ee:ff",
            hostname="workstation-01",
            services=["ssh", "http"]
        )

        self.assertEqual(host.ip, "192.168.1.100")
        self.assertEqual(host.mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(len(host.services), 2)

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_captured_credential(self):
        """Test CapturedCredential data model"""
        cred = CapturedCredential(
            type="ntlm_hash",
            username="DOMAIN\\Administrator",
            value="5ebcb87da5a29ddd1cc01ca6f6a94c58",
            source_ip="192.168.1.50",
            source_protocol="llmnr",
            timestamp=datetime.now().isoformat()
        )

        self.assertEqual(cred.type, "ntlm_hash")
        self.assertEqual(cred.username, "DOMAIN\\Administrator")
        self.assertIn("NTLM", cred.type.upper())

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_wireless_network(self):
        """Test WirelessNetwork data model"""
        network = WirelessNetwork(
            ssid="OfficeWiFi",
            bssid="00:11:22:33:44:55",
            channel=6,
            signal_strength=-45,
            encryption="WPA2"
        )

        self.assertEqual(network.ssid, "OfficeWiFi")
        self.assertEqual(network.channel, 6)
        self.assertEqual(network.encryption, "WPA2")
        self.assertFalse(network.handshake_captured)


class TestLayer2Attacks(unittest.TestCase):
    """Test Layer 2 attack structures"""

    def setUp(self):
        """Initialize attack modules"""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = Path(self.temp_dir) / "test.log"
        self.scope_file = Path(self.temp_dir) / "scope.txt"
        self.scope_file.write_text("192.168.1.0/24\n")

        self.logger = Logger(str(self.log_file))
        self.scope = ScopeValidator(str(self.scope_file))

    def tearDown(self):
        """Clean up"""
        for f in [self.log_file, self.scope_file]:
            if f.exists():
                f.unlink()
        os.rmdir(self.temp_dir)

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_layer2_attacks_initialization(self):
        """Test Layer2Attacks module initialization"""
        l2 = Layer2Attacks(self.logger, self.scope)
        self.assertIsNotNone(l2)
        self.assertEqual(len(l2.running_attacks), 0)

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_out_of_scope_blocks_arp_spoof(self):
        """Test that out-of-scope targets are blocked"""
        l2 = Layer2Attacks(self.logger, self.scope)

        # Try to spoof out-of-scope target
        with self.assertRaises(AuthorizationError):
            l2.arp_spoof("10.0.0.1", "192.168.1.1")  # 10.0.0.1 not in scope

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_out_of_scope_blocks_arp_mitm(self):
        """Test that out-of-scope targets block MITM"""
        l2 = Layer2Attacks(self.logger, self.scope)

        # Try MITM with out-of-scope target
        with self.assertRaises(AuthorizationError):
            l2.arp_mitm("192.168.1.100", "10.0.0.1")  # 10.0.0.1 not in scope


class TestCredentialCapture(unittest.TestCase):
    """Test credential capture modules"""

    def setUp(self):
        """Initialize credential capture"""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = Path(self.temp_dir) / "test.log"
        self.scope_file = Path(self.temp_dir) / "scope.txt"
        self.scope_file.write_text("192.168.1.0/24\n")

        self.logger = Logger(str(self.log_file))
        self.scope = ScopeValidator(str(self.scope_file))

    def tearDown(self):
        """Clean up"""
        for f in [self.log_file, self.scope_file]:
            if f.exists():
                f.unlink()
        os.rmdir(self.temp_dir)

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_credential_capture_initialization(self):
        """Test CredentialCapture module initialization"""
        creds = CredentialCapture(self.logger, self.scope)
        self.assertIsNotNone(creds)
        self.assertEqual(len(creds.captured_credentials), 0)


class TestKerberosAttacks(unittest.TestCase):
    """Test Kerberos attack structures"""

    def setUp(self):
        """Initialize Kerberos module"""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = Path(self.temp_dir) / "test.log"
        self.scope_file = Path(self.temp_dir) / "scope.txt"
        self.scope_file.write_text("192.168.1.0/24\n")

        self.logger = Logger(str(self.log_file))
        self.scope = ScopeValidator(str(self.scope_file))

    def tearDown(self):
        """Clean up"""
        for f in [self.log_file, self.scope_file]:
            if f.exists():
                f.unlink()
        os.rmdir(self.temp_dir)

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_kerberos_attacks_initialization(self):
        """Test KerberosAttacks module initialization"""
        krb = KerberosAttacks(self.logger, self.scope)
        self.assertIsNotNone(krb)


class TestNetworkRecon(unittest.TestCase):
    """Test network reconnaissance"""

    def setUp(self):
        """Initialize recon module"""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = Path(self.temp_dir) / "test.log"
        self.scope_file = Path(self.temp_dir) / "scope.txt"
        self.scope_file.write_text("192.168.1.0/24\n")

        self.logger = Logger(str(self.log_file))
        self.scope = ScopeValidator(str(self.scope_file))

    def tearDown(self):
        """Clean up"""
        for f in [self.log_file, self.scope_file]:
            if f.exists():
                f.unlink()
        os.rmdir(self.temp_dir)

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_network_recon_initialization(self):
        """Test NetworkRecon module initialization"""
        recon = NetworkRecon(self.logger, self.scope)
        self.assertIsNotNone(recon)


class TestWirelessAttacks(unittest.TestCase):
    """Test wireless attack modules"""

    def setUp(self):
        """Initialize wireless module"""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = Path(self.temp_dir) / "test.log"
        self.scope_file = Path(self.temp_dir) / "scope.txt"
        self.scope_file.write_text("192.168.1.0/24\n")

        self.logger = Logger(str(self.log_file))
        self.scope = ScopeValidator(str(self.scope_file))

    def tearDown(self):
        """Clean up"""
        for f in [self.log_file, self.scope_file]:
            if f.exists():
                f.unlink()
        os.rmdir(self.temp_dir)

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_wireless_attacks_initialization(self):
        """Test WirelessAttacks module initialization"""
        wireless = WirelessAttacks(self.logger, self.scope)
        self.assertIsNotNone(wireless)


class TestAttackChains(unittest.TestCase):
    """Test pre-built attack chains"""

    def setUp(self):
        """Initialize attack chains"""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = Path(self.temp_dir) / "test.log"
        self.scope_file = Path(self.temp_dir) / "scope.txt"
        self.scope_file.write_text("192.168.1.0/24\n")

        self.logger = Logger(str(self.log_file))
        self.scope = ScopeValidator(str(self.scope_file))

    def tearDown(self):
        """Clean up"""
        for f in [self.log_file, self.scope_file]:
            if f.exists():
                f.unlink()
        os.rmdir(self.temp_dir)

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_attack_chains_initialization(self):
        """Test AttackChains module initialization"""
        chains = AttackChains(self.logger, self.scope)
        self.assertIsNotNone(chains)


class TestIntegration(unittest.TestCase):
    """Integration tests"""

    def setUp(self):
        """Setup integration test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = Path(self.temp_dir) / "test.log"
        self.scope_file = Path(self.temp_dir) / "scope.txt"
        self.scope_file.write_text("192.168.1.0/24\n10.0.0.0/8\n")

    def tearDown(self):
        """Clean up"""
        for f in [self.log_file, self.scope_file]:
            if f.exists():
                f.unlink()
        os.rmdir(self.temp_dir)

    @unittest.skipUnless(MODULE_AVAILABLE, f"Module not available: {IMPORT_ERROR}")
    def test_full_module_chain(self):
        """Test initialization of all modules together"""
        logger = Logger(str(self.log_file))
        scope = ScopeValidator(str(self.scope_file))

        # Verify all modules can be initialized
        l2 = Layer2Attacks(logger, scope)
        creds = CredentialCapture(logger, scope)
        krb = KerberosAttacks(logger, scope)
        recon = NetworkRecon(logger, scope)
        wireless = WirelessAttacks(logger, scope)
        chains = AttackChains(logger, scope)

        # All should be non-None
        self.assertIsNotNone(l2)
        self.assertIsNotNone(creds)
        self.assertIsNotNone(krb)
        self.assertIsNotNone(recon)
        self.assertIsNotNone(wireless)
        self.assertIsNotNone(chains)


def run_tests():
    """Run all tests"""
    if not MODULE_AVAILABLE:
        print(f"[!] Cannot run tests: {IMPORT_ERROR}")
        print("[*] Install dependencies: pip install scapy impacket")
        return 1

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test cases
    suite.addTests(loader.loadTestsFromTestCase(TestLogger))
    suite.addTests(loader.loadTestsFromTestCase(TestScopeValidator))
    suite.addTests(loader.loadTestsFromTestCase(TestDataModels))
    suite.addTests(loader.loadTestsFromTestCase(TestLayer2Attacks))
    suite.addTests(loader.loadTestsFromTestCase(TestCredentialCapture))
    suite.addTests(loader.loadTestsFromTestCase(TestKerberosAttacks))
    suite.addTests(loader.loadTestsFromTestCase(TestNetworkRecon))
    suite.addTests(loader.loadTestsFromTestCase(TestWirelessAttacks))
    suite.addTests(loader.loadTestsFromTestCase(TestAttackChains))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    import sys
    sys.exit(run_tests())
