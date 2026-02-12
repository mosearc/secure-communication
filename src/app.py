import argparse
import sys
import socket
from datetime import datetime, timezone

from pathlib import Path
from rsa import RSA
from dh import DiffieHellman
from aes import AES_GCM
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

debug_levels = {
    "ERROR": 0,
    "WARN": 1,
    "INFO": 2,
    "DEBUG": 2
}

MAX_PACKET_SIZE = 1024 * 1024  # 1 MiB safety limit for framed packets

class SecureCommunicationApp:
    def __init__(self, role, host='127.0.0.1', port=65432, debug_level=0):
        self.role = role
        self.host = host
        self.port = port
        self.debug_level = debug_level
        self.username = role
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_cert_fingerprint = None
        self.rsa = RSA()
        self.dh = DiffieHellman()
        self.session_key = None
        self.aes = None

    def log(self, message, debug_level):
        """Utility function for logging messages with different levels."""
        lvl_int = debug_levels[debug_level]
        if lvl_int > self.debug_level:
            return

        if lvl_int == 0:
            print(f"\033[91m[{debug_level}] {message}\033[0m")  # Red text
        elif lvl_int == 1:
            print(f"\033[93m[{debug_level}] {message}\033[0m")  # Yellow text
        elif lvl_int == 2:
            print(f"\033[0;36m[{debug_level}] {message}\033[0m")  # Blue text
        else:
            print(f"{debug_level} {message}")

    def start(self):
        """
        Generate or load local certificates and start the client/server loop.
        """
        cert_dir = Path("certs")
        key_path = cert_dir / f"{self.role}.key"
        cert_path = cert_dir / f"{self.role}.crt"

        if not key_path.exists() or not cert_path.exists():
            try:
                key_path, cert_path = self.rsa.generate_ca_signed_cert(self.role, 2048, cert_dir)
            except Exception as exc:
                self.log(f"Certificate generation failed: {exc}", "ERROR")
                return
    
        self.key_path = key_path
        self.cert_path = cert_path
        # Bind this app's key/cert so RSA helpers can load them internally.
        self.rsa.set_paths(key_path, cert_path)
        self.log(f"Using cert {cert_path} and key {key_path}", "INFO")

        if self.role == 'server':
            self.start_server()
        elif self.role == 'client':
            self.start_client()
        else:
            self.log("Invalid role specified. Use --server or --client.", "ERROR")

    def start_server(self):
        """
        Bind and listen for a single incoming connection as the server.
        """
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        self.log(f"Server listening on {self.host}:{self.port}", "INFO")
        client_socket, addr = self.socket.accept()
        self.log(f"Connection established with {addr}", "INFO")
        self.handle_connection(client_socket, server_mode=True)

    def start_client(self):
        """
        Connect to the server and enter the secure communication loop.
        """
        self.socket.connect((self.host, self.port))
        self.log(f"Connected to server at {self.host}:{self.port}", "INFO")
        self.handle_connection(self.socket, server_mode=False)

    def handle_connection(self, conn_socket, server_mode):
        """
        Run the authenticated handshake and encrypted message loop.

        Args:
            conn_socket (socket.socket): Connected socket.
            server_mode (bool): True when acting as server.
        """
        try:
            # Placeholder for key exchange
            self.key_exchange(conn_socket, server_mode)

            if self.session_key is None:
                raise RuntimeError("Key exchange failed. Closing connection.")

            while True:
                if server_mode:
                    # Server receiving a message
                    data = self.recv_packet(conn_socket)
                    if data is None:
                        break
                    self.log(f"Received (encrypted): {data}", "DEBUG")

                    # decrypting the message
                    try:
                        message = self.unprotect_message(data)
                    except Exception as e:
                        self.log(f"SECURITY VIOLATION: {e}", "ERROR")
                        break  # CLOSE IMMEDIATELY

                    if message == b"CLOSE_NOTIFY":
                        self.log("Client requested secure close. Sending ACK.", "INFO")
                        try:
                            response = self.protect_message(b"CLOSE_ACK")
                            self.send_packet(conn_socket, response)
                        except Exception:
                            pass  # If we can't send ACK, just close.
                        break

                    print(f"Received: {message.decode()}")

                    try:
                        response = self.protect_message(b"ACK")
                        self.send_packet(conn_socket, response)
                        self.log(f"Sent: {response}", "DEBUG")
                    except Exception as e:
                        self.log(f"Failed to send ACK: {e}", "ERROR")
                        break

                else:  # CLIENT
                    try:
                        user_input = input("Enter message to send (exit or quit to close the connection): ")
                    except EOFError:
                        user_input = "exit"

                    if not user_input: continue

                    if user_input.lower() in ['exit', 'quit']:
                        self.log("Sending close notification...", "INFO")
                        # Encrypt and send CLOSE_NOTIFY
                        try:
                            encrypted_msg = self.protect_message(b"CLOSE_NOTIFY")
                            self.send_packet(conn_socket, encrypted_msg)

                            self.log("Waiting for Server ACK...", "DEBUG")
                            ack_data = self.recv_packet(conn_socket)

                            if ack_data is not None:
                                ack_plain = self.unprotect_message(ack_data)
                                if ack_plain == b"CLOSE_ACK":
                                    self.log("Received CLOSE_ACK. Secure shutdown complete.", "INFO")
                                else:
                                    self.log(f"Shutdown Error: Expected CLOSE_ACK, got {ack_plain}", "WARN")
                            else:
                                self.log("Server closed connection without ACK.", "WARN")

                        except Exception as e:
                            self.log(f"Failed to send close notify: {e}", "ERROR")
                        break

                    try:
                        message = user_input.encode()
                        encrypted_message = self.protect_message(message)
                        self.send_packet(conn_socket, encrypted_message)
                        self.log(f"Sent: {encrypted_message}", "DEBUG")
                    except Exception as e:
                        self.log(f"Encryption failed: {e}", "ERROR")
                        break  # CLOSE IMMEDIATELY

                    # Receive response
                    data = self.recv_packet(conn_socket)
                    if data is None:
                        break

                    # decrypting the response
                    self.log(f"Server response (encrypted): {data}", "DEBUG")
                    try:
                        response = self.unprotect_message(data)
                    except Exception as e:
                        self.log(f"SECURITY VIOLATION: {e}", "ERROR")
                        break  # CLOSE IMMEDIATELY

                    if response == b"CLOSE_ACK":
                        self.log("Server acknowledged close.", "INFO")
                        break
                    print(f"Server response: {response.decode()}")

        except Exception as e:
            self.log(f"An error occurred: {e}", "ERROR")
        finally:
            self.clear_session_state()
            conn_socket.close()

    def key_exchange(self, conn_socket, server_mode):
        """
        Exchange peer certificates, verify them, and derive a shared session key.

        This method signs the DH nonce/public key payload and verifies the
        peer's signature using the peer certificate.
        On success, it sets self.session_key and initializes the AES-GCM channel.

        Args:
            conn_socket (socket.socket): Connected socket.
            server_mode (bool): True when acting as server.
        """
        # Exchange and verify certificates before DH-based authentication.
        ca_cert = self.load_ca_cert()
        local_cert_bytes = Path(self.cert_path).read_bytes()

        if server_mode:
            peer_len = int.from_bytes(self.recv_exact(conn_socket, 4), "big")
            peer_cert_bytes = self.recv_exact(conn_socket, peer_len)
            conn_socket.sendall(len(local_cert_bytes).to_bytes(4, "big"))
            conn_socket.sendall(local_cert_bytes)
        else:
            conn_socket.sendall(len(local_cert_bytes).to_bytes(4, "big"))
            conn_socket.sendall(local_cert_bytes)
            peer_len = int.from_bytes(self.recv_exact(conn_socket, 4), "big")
            peer_cert_bytes = self.recv_exact(conn_socket, peer_len)

        # Expect the opposite role on the peer when validating its certificate.
        try:
            expected_peer_role = "client" if server_mode else "server"
            self.verify_peer_cert(peer_cert_bytes, ca_cert, expected_peer_role)
        except Exception as exc:
            self.disconnect_with_error(conn_socket, "Peer certificate verification failed", exc)

        self.rsa.set_peer_cert_bytes(peer_cert_bytes)
        self.log("Peer certificate verified against CA.", "INFO")

        # Diffie-Hellman exchange with nonce binding for the session key.
        private_dh_key = self.dh.generate_private_key()
        public_dh_key = self.dh.generate_public_key(private_dh_key)
        local_nonce = self.dh.generate_nonce()
        # Send nonce + DH public key together with a signature.
        message = self.pack_dh_message(local_nonce, public_dh_key)

        if server_mode:
            total_len = int.from_bytes(self.recv_exact(conn_socket, 4), "big")
            peer_message = self.recv_exact(conn_socket, total_len)
            conn_socket.sendall(len(message).to_bytes(4, "big") + message)
        else:
            conn_socket.sendall(len(message).to_bytes(4, "big") + message)
            total_len = int.from_bytes(self.recv_exact(conn_socket, 4), "big")
            peer_message = self.recv_exact(conn_socket, total_len)

        # Parse and verify the peer's signed DH payload.
        try:
            peer_nonce, peer_public_key = self.unpack_dh_message(peer_message)
        except Exception as exc:
            self.disconnect_with_error(conn_socket, "Peer DH signature verification failed", exc)

        # Check for replayed nonces.
        self.dh.check_fresh_nonce(peer_nonce)

        if server_mode:
            # Server treats peer nonce as rand_a and its own as rand_b.
            self.dh.set_nonces(peer_nonce, local_nonce)
        else:
            # Client treats its own nonce as rand_a and peer as rand_b.
            self.dh.set_nonces(local_nonce, peer_nonce)

        # Derive the shared secret and session key for later message protection.
        shared_secret = self.dh.compute_shared_secret(private_dh_key, peer_public_key)
        self.session_key = self.dh.derive_key(shared_secret)
        self.log("Derived session key using Diffie-Hellman.", "INFO")
        self.aes = AES_GCM(self.session_key)

    def pack_dh_message(self, nonce, public_key):
        """
        Pack nonce + DH public key + signature into a single message.

        Args:
            nonce (bytes): Local nonce.
            public_key (int): Local DH public key.

        Returns:
            bytes: Serialized message.
        """
        public_key_bytes = public_key.to_bytes((public_key.bit_length() + 7) // 8, "big")
        payload = (
            len(nonce).to_bytes(4, "big")
            + nonce
            + len(public_key_bytes).to_bytes(4, "big")
            + public_key_bytes
        )

        signature = self.rsa.rsa_sign(payload)
        signature_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, "big")
        return payload + len(signature_bytes).to_bytes(4, "big") + signature_bytes

    def unpack_dh_message(self, message):
        """
        Unpack nonce + DH public key + signature and verify the signature.

        Args:
            message (bytes): Serialized message from peer.

        Returns:
            tuple: `(peer_nonce, peer_public_key)`.
        """
        offset = 0
        nonce_len = int.from_bytes(message[offset:offset + 4], "big")
        offset += 4
        peer_nonce = message[offset:offset + nonce_len]
        offset += nonce_len
        pub_len = int.from_bytes(message[offset:offset + 4], "big")
        offset += 4
        pub_bytes = message[offset:offset + pub_len]
        offset += pub_len
        sig_len = int.from_bytes(message[offset:offset + 4], "big")
        offset += 4
        sig_bytes = message[offset:offset + sig_len]

        payload = (
            nonce_len.to_bytes(4, "big")
            + peer_nonce
            + pub_len.to_bytes(4, "big")
            + pub_bytes
        )

        signature = int.from_bytes(sig_bytes, "big")
        if not self.rsa.rsa_verify_peer(payload, signature):
            raise ValueError("peer DH signature invalid")
        return peer_nonce, int.from_bytes(pub_bytes, "big")
    
    def disconnect_with_error(self, conn_socket, message, exc):
        """
        Log an error, close the socket, and raise a runtime error.

        Args:
            conn_socket (socket.socket): Connected socket.
            message (str): Error message to log.
            exc (Exception): Original exception.
        """
        self.log(f"{message}: {exc}", "ERROR")
        try:
            error_bytes = f"ERROR: {message}".encode()
            conn_socket.sendall(len(error_bytes).to_bytes(4, "big") + error_bytes)
        except Exception:
            pass
        conn_socket.close()
        raise RuntimeError(message) from exc

    
    def protect_message(self, message):
        """
        Encrypt and authenticate a message using the active session key.

        Args:
            message (bytes): Plaintext message to protect.

        Returns:
            bytes: Encrypted packet ready for transport.
        """
        if self.aes is None:
            self.log("Channel not ready.", "WARN")
            raise ConnectionError("Secure channel not active. Cannot encrypt.")
        return self.aes.enc(message)

    def unprotect_message(self, data):
        """
        Decrypt and authenticate an incoming packet.

        Args:
            data (bytes): Encrypted packet from the peer.

        Returns:
            bytes: Decrypted plaintext message.
        """
        if self.aes is None:
            self.log("Channel not ready.", "WARN")
            raise ConnectionError("Secure channel not active. Cannot decrypt.")
        return self.aes.dec(data)

    def clear_session_state(self):
        """
        Clear session keys and channel state on shutdown.
        """
        self.session_key = None
        self.aes = None
        self.peer_cert_fingerprint = None

    def recv_exact(self, conn_socket, nbytes):
        """
        Receive exactly nbytes from a socket or raise on disconnect.

        Args:
            conn_socket (socket.socket): Connected socket.
            nbytes (int): Number of bytes to read.

        Returns:
            bytes: Received data.
        """
        chunks = []
        remaining = nbytes
        while remaining > 0:
            chunk = conn_socket.recv(remaining)
            if not chunk:
                raise ConnectionError("connection closed during receive")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def send_packet(self, conn_socket, payload):
        """
        Send a length-prefixed payload over the socket.

        TCP is a byte stream, so explicit length framing preserves message
        boundaries for encrypted packets.

        Args:
            conn_socket (socket.socket): Connected socket.
            payload (bytes): Payload to send.
        """
        conn_socket.sendall(len(payload).to_bytes(4, "big") + payload)

    def recv_packet(self, conn_socket):
        """
        Receive a length-prefixed payload, or return None on clean EOF.

        Length framing ensures one complete encrypted packet is read before
        decryption, avoiding partial or concatenated reads.

        Args:
            conn_socket (socket.socket): Connected socket.

        Returns:
            bytes | None: Received payload, or None if the peer closed cleanly.
        """
        try:
            length_bytes = self.recv_exact(conn_socket, 4)
        except ConnectionError:
            return None

        total_len = int.from_bytes(length_bytes, "big")
        if total_len > MAX_PACKET_SIZE:
            raise ValueError(f"packet too large: {total_len} bytes")
        if total_len == 0:
            raise ValueError("zero-length packet is invalid")
        return self.recv_exact(conn_socket, total_len)

    def load_ca_cert(self):
        """
        Load the CA certificate from certs/ca.crt.

        Returns:
            x509.Certificate: Loaded CA certificate.
        """
        ca_path = Path("certs") / "ca.crt"
        if not ca_path.exists():
            raise RuntimeError("CA certificate missing: certs/ca.crt")
        return x509.load_pem_x509_certificate(ca_path.read_bytes())

    def verify_peer_cert(self, peer_cert_bytes, ca_cert, expected_peer_role):
        """
        Verify a peer certificate against the CA and cache its fingerprint.

        This validates the issuing CA, enforces a single CN that matches the
        expected peer role, and checks the certificate validity window before
        caching the fingerprint.

        Args:
            peer_cert_bytes (bytes): PEM-encoded peer certificate.
            ca_cert (x509.Certificate): Trusted CA certificate.
            expected_peer_role (str): Expected peer role (e.g., "client" or "server").

        Raises:
            ValueError: If the certificate fails issuer, role, or validity checks.
        """
        peer_cert = x509.load_pem_x509_certificate(peer_cert_bytes)
        fingerprint = peer_cert.fingerprint(hashes.SHA256())
        if self.peer_cert_fingerprint == fingerprint:
            return
        if peer_cert.issuer != ca_cert.subject:
            raise ValueError("peer certificate not issued by trusted CA")

        # Enforce exactly one CN to avoid ambiguous role validation.
        common_names = peer_cert.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )
        if len(common_names) != 1:
            raise ValueError(
                f"peer certificate must contain exactly one CN, got {len(common_names)}"
            )
        common_name = common_names[0].value
        if common_name != expected_peer_role:
            raise ValueError(
                f"peer certificate role mismatch: expected {expected_peer_role}, got {common_name}"
            )

        # Reject certificates that are not currently within their validity window.
        not_before = peer_cert.not_valid_before_utc
        not_after = peer_cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        if now < not_before or now > not_after:
            raise ValueError("peer certificate is not currently valid")

        ca_cert.public_key().verify(
            peer_cert.signature,
            peer_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            peer_cert.signature_hash_algorithm,
        )
        self.peer_cert_fingerprint = fingerprint


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action="store_true", help="Run as server")
    parser.add_argument("--client", action="store_true", help="Run as client")
    parser.add_argument("--debug-level", type=int, choices=[0, 1, 2], default=0,
                        help="Debug level: 0 for ERROR, 1 for WARNING, 2 for INFO/DEBUG.")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Hostname to bind/connect to")
    parser.add_argument("--port", type=int, default=65432, help="Port to bind/connect to")

    args = parser.parse_args()

    if args.server:
        role = 'server'
    elif args.client:
        role = 'client'
    else:
        print("\033[91m[ERROR] Please specify either --server or --client\033[0m")
        sys.exit(1)

    app = SecureCommunicationApp(role, host=args.host, port=args.port, debug_level=args.debug_level)
    app.start()


if __name__ == "__main__":
    main()
