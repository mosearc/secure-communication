import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from dh import DiffieHellman


class TestDiffieHellman(unittest.TestCase):
    def test_shared_secret_symmetry(self):
        """Compute shared secrets from both sides and confirm they match."""
        dh_a = DiffieHellman()
        dh_b = DiffieHellman()

        priv_a = dh_a.generate_private_key()
        priv_b = dh_b.generate_private_key()
        pub_a = dh_a.generate_public_key(priv_a)
        pub_b = dh_b.generate_public_key(priv_b)

        secret_a = dh_a.compute_shared_secret(priv_a, pub_b)
        secret_b = dh_b.compute_shared_secret(priv_b, pub_a)
        self.assertEqual(secret_a, secret_b)

    def test_derive_key_requires_nonces(self):
        """Ensure derive_key rejects calls before nonces are set."""
        dh = DiffieHellman()
        with self.assertRaises(ValueError):
            dh.derive_key(12345)

    def test_derive_key_length(self):
        """Confirm derive_key honors the requested output length."""
        dh = DiffieHellman()
        dh.set_nonces(dh.generate_nonce(), dh.generate_nonce())
        key = dh.derive_key(12345, length=16)
        self.assertEqual(len(key), 16)

    def test_check_fresh_nonce_rejects_replay(self):
        """Reject the same nonce when checked twice within the TTL."""
        dh = DiffieHellman()
        nonce = dh.generate_nonce()
        dh.check_fresh_nonce(nonce)
        with self.assertRaises(ValueError):
            dh.check_fresh_nonce(nonce)


if __name__ == "__main__":
    unittest.main()
