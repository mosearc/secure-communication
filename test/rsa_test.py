import atexit
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from rsa import RSA

_TMPDIR = None
_KEY_PATH = None
_CERT_PATH = None
_CERT_BYTES = None


class TestRSA(unittest.TestCase):
    def setUp(self):
        """Reuse a cached cert/key pair and bind paths to a fresh RSA instance."""
        global _TMPDIR, _KEY_PATH, _CERT_PATH, _CERT_BYTES
        if _TMPDIR is None:
            _TMPDIR = tempfile.TemporaryDirectory()
            atexit.register(_TMPDIR.cleanup)
            cert_dir = Path(_TMPDIR.name)
            rsa = RSA()
            _KEY_PATH, _CERT_PATH = rsa.generate_ca_signed_cert(
                "tester", 2048, cert_dir
            )
            _CERT_BYTES = Path(_CERT_PATH).read_bytes()

        self.rsa = RSA()
        self.rsa.set_paths(_KEY_PATH, _CERT_PATH)

    def test_rsa_verify_peer(self):
        """Verify a signed message using the peer certificate bytes."""
        message = b"peer message"
        signature = self.rsa.rsa_sign(message)

        verifier = RSA()
        verifier.set_peer_cert_bytes(_CERT_BYTES)
        self.assertTrue(verifier.rsa_verify_peer(message, signature))

    def test_rsa_verify_rejects_bad_signature(self):
        """Reject altered signatures that do not match the message."""
        message = b"hello world"
        signature = self.rsa.rsa_sign(message)
        verifier = RSA()
        verifier.set_peer_cert_bytes(_CERT_BYTES)
        self.assertFalse(verifier.rsa_verify_peer(message, signature + 1))

    def test_rsa_sign_requires_paths(self):
        """Ensure signing fails until key/cert paths are configured."""
        rsa = RSA()
        with self.assertRaises(ValueError):
            rsa.rsa_sign(b"no paths")

    def test_rsa_verify_peer_requires_cert(self):
        """Ensure peer verification fails without a loaded peer certificate."""
        rsa = RSA()
        with self.assertRaises(ValueError):
            rsa.rsa_verify_peer(b"msg", 123)

    def test_generate_ca_and_cert_files(self):
        """Generate CA and leaf certs and confirm files exist on disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_dir = Path(tmpdir)
            rsa = RSA()
            ca_key_path, ca_cert_path = rsa.generate_ca("UnitTestCA", 2048, cert_dir)
            self.assertTrue(ca_key_path.exists())
            self.assertTrue(ca_cert_path.exists())

            key_path, cert_path = rsa.generate_ca_signed_cert("unit", 2048, cert_dir)
            self.assertTrue(key_path.exists())
            self.assertTrue(cert_path.exists())


if __name__ == "__main__":
    unittest.main()
