import os
import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from aes import AES_GCM


class TestAES_GCM(unittest.TestCase):
    def setUp(self):
        """Sets up the channel for testing."""
        self.session_key = os.urandom(32)  # 256-bit key
        self.alice = AES_GCM(self.session_key)
        self.bob = AES_GCM(self.session_key)

    def test_encryption_decryption(self):
        """Test that a message encrypted by Alice can be decrypted by Bob."""
        plaintext = b"Hello, World!"
        packet = self.alice.enc(plaintext)
        decrypted = self.bob.dec(packet)
        self.assertEqual(plaintext, decrypted)

    def test_integrity_tampering_tag(self):
        """Test modifications in the Tag cause decryption to fail."""
        packet = bytearray(self.alice.enc(b"Sensitive Data"))

        # Corrupt the last byte
        packet[-1] ^= 0xFF

        with self.assertRaises(ValueError):
            self.bob.dec(bytes(packet))

    def test_integrity_tampering_header(self):
        """
        Test modifications to the Sequence Number (AAD).
        Even though SeqNum is cleartext, it is integrity protected.
        Modifying it should fail the Tag check.
        """
        packet = bytearray(self.alice.enc(b"Data"))

        # Corrupt the first byte (part of the Sequence Number)
        packet[0] ^= 0xFF

        with self.assertRaises(ValueError):
            self.bob.dec(bytes(packet))

    def test_replay_attack_protection(self):
        """Test the same packet cannot be processed twice."""
        packet = self.alice.enc(b"Money Transfer")

        # First receive: Should work
        self.bob.dec(packet)

        # Second receive (Replay): Should fail
        with self.assertRaises(ValueError) as cm:
            self.bob.dec(packet)
        self.assertIn("Replay detected", str(cm.exception))

    def test_reordering_protection(self):
        """Old packets arriving late are rejected."""
        packet_1 = self.alice.enc(b"Message 1")
        packet_2 = self.alice.enc(b"Message 2")

        # Bob receives Message 2 first (Seq 2)
        self.bob.dec(packet_2)

        # Bob receives Message 1 later (Seq 1): Should be rejected
        with self.assertRaises(ValueError) as cm:
            self.bob.dec(packet_1)
        self.assertIn("Replay detected", str(cm.exception))

    def test_wrong_key(self):
        """Test channel with a different key (should fail)."""
        eve_key = os.urandom(32)
        eve = AES_GCM(eve_key)

        packet = self.alice.enc(b"Secret")
        with self.assertRaises(ValueError):
            eve.dec(packet)



if __name__ == '__main__':
    unittest.main()
