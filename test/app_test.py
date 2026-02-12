import sys
import unittest
from pathlib import Path
import socket
import tempfile
from unittest.mock import Mock, patch

from cryptography import x509

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from app import MAX_PACKET_SIZE, SecureCommunicationApp
from dh import DiffieHellman
from rsa import RSA


class TestSecureCommunicationApp(unittest.TestCase):
    def _make_app(self, role="server"):
        """Create an app instance without opening a real socket."""
        with patch("app.socket.socket", return_value=Mock()):
            return SecureCommunicationApp(role)

    def _build_cert_bundle(self):
        """Create a CA and leaf certs for testing."""
        tmpdir = tempfile.TemporaryDirectory()
        cert_dir = Path(tmpdir.name)
        rsa = RSA()
        key_path, cert_path = rsa.generate_ca_signed_cert("tester", 2048, cert_dir)
        ca_cert = x509.load_pem_x509_certificate((cert_dir / "ca.crt").read_bytes())
        cert_bytes = Path(cert_path).read_bytes()
        return tmpdir, key_path, cert_path, ca_cert, cert_bytes

    def test_pack_unpack_dh_message(self):
        """Pack and unpack a signed DH message with valid peer cert bytes."""
        tmpdir, key_path, cert_path, _ca_cert, cert_bytes = self._build_cert_bundle()
        self.addCleanup(tmpdir.cleanup)

        app = self._make_app("server")
        app.rsa.set_paths(key_path, cert_path)
        app.rsa.set_peer_cert_bytes(cert_bytes)

        dh = DiffieHellman()
        nonce = dh.generate_nonce()
        private_key = dh.generate_private_key()
        public_key = dh.generate_public_key(private_key)

        message = app.pack_dh_message(nonce, public_key)
        unpacked_nonce, unpacked_pub = app.unpack_dh_message(message)
        self.assertEqual(unpacked_nonce, nonce)
        self.assertEqual(unpacked_pub, public_key)

    def test_verify_peer_cert_role_mismatch(self):
        """Reject certificates whose CN does not match the expected peer role."""
        tmpdir, _key_path, cert_path, ca_cert, _cert_bytes = self._build_cert_bundle()
        self.addCleanup(tmpdir.cleanup)

        app = self._make_app("server")
        peer_cert_bytes = Path(cert_path).read_bytes()
        with self.assertRaises(ValueError):
            app.verify_peer_cert(peer_cert_bytes, ca_cert, expected_peer_role="client")

    def test_verify_peer_cert_accepts_expected_role(self):
        """Accept peer certs with a matching CN and valid issuer."""
        tmpdir, _key_path, cert_path, ca_cert, cert_bytes = self._build_cert_bundle()
        self.addCleanup(tmpdir.cleanup)

        app = self._make_app("server")
        app.verify_peer_cert(cert_bytes, ca_cert, expected_peer_role="tester")

    def test_recv_packet_size_guard(self):
        """Reject framed packets that exceed MAX_PACKET_SIZE."""
        app = self._make_app("server")
        length_bytes = (MAX_PACKET_SIZE + 1).to_bytes(4, "big")
        with patch.object(app, "recv_exact", return_value=length_bytes):
            with self.assertRaises(ValueError):
                app.recv_packet(None)

    def test_recv_packet_rejects_zero_length(self):
        """Reject zero-length framed packets."""
        app = self._make_app("server")
        length_bytes = (0).to_bytes(4, "big")
        with patch.object(app, "recv_exact", return_value=length_bytes):
            with self.assertRaises(ValueError):
                app.recv_packet(None)


if __name__ == "__main__":
    unittest.main()
