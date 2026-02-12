import hashlib
import secrets
import time


class DiffieHellman:
    """
    Minimal Diffie-Hellman helper using a fixed safe prime group.
    """

    # RFC 3526 group 14 (2048-bit) prime, generator 2
    # https://www.rfc-editor.org/rfc/rfc3526#section-3
    _P = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
        "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE65381FFFFFFFFFFFFFFFF",
        16,
    )
    _G = 2
    _NONCE_TTL_SECONDS = 600  # 10 minutes
    _MAX_NONCE_CACHE = 2048

    def __init__(self):
        """
        Initialize Diffie-Hellman using the fixed RFC 3526 group.

        Returns:
            None
        """
        self.p = self._P
        self.g = self._G
        self.rand_a = None
        self.rand_b = None
        self._seen_nonces = {}

    def set_nonces(self, rand_a, rand_b):
        """
        Store the two-party nonces used for session key derivation.

        Args:
            rand_a (bytes): Initiator nonce.
            rand_b (bytes): Responder nonce.

        Returns:
            None
        """
        self.rand_a = rand_a
        self.rand_b = rand_b

    def generate_private_key(self):
        """
        Generate a random private key.

        Returns:
            int: Private key x where 2 <= x <= p-2.
        """
        return secrets.randbelow(self.p - 3) + 2

    def generate_public_key(self, private_key):
        """
        Compute the public key g^x mod p.

        Args:
            private_key (int): Private key x.

        Returns:
            int: Public key value.
        """
        return pow(self.g, private_key, self.p)

    def compute_shared_secret(self, private_key, peer_public_key):
        """
        Compute the shared secret from a peer public key.

        Args:
            private_key (int): Local private key.
            peer_public_key (int): Peer public key.

        Returns:
            int: Shared secret value.
        """
        return pow(peer_public_key, private_key, self.p)

    def derive_key(self, shared_secret, length=32):
        """
        Derive a fixed-length session key from the shared secret and nonces.

        Args:
            shared_secret (int): Shared secret value.
            length (int): Output length in bytes.

        Returns:
            bytes: Derived key bytes.
        """
        if self.rand_a is None or self.rand_b is None:
            raise ValueError("derive_key requires set_nonces() to be called first")

        secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")
        digest = hashlib.sha256(secret_bytes + self.rand_a + self.rand_b).digest()
        return digest[:length]

    def generate_nonce(self, length=32):
        """
        Generate a cryptographic nonce.

        Args:
            length (int): Output length in bytes.

        Returns:
            bytes: Random nonce bytes.
        """
        return secrets.token_bytes(length)

    def check_fresh_nonce(self, nonce):
        """
        Reject replayed handshake nonces within a short time window.

        Args:
            nonce (bytes): Peer nonce to validate.
        """
        now = time.time()
        # Remove expired nonces to keep the cache bounded in time.
        for n, ts in list(self._seen_nonces.items()):
            if now - ts > self._NONCE_TTL_SECONDS:
                del self._seen_nonces[n]

        if nonce in self._seen_nonces:
            raise ValueError("handshake nonce replay detected")
        if len(self._seen_nonces) >= self._MAX_NONCE_CACHE:
            # Evict the oldest entry to avoid unbounded growth.
            oldest = min(self._seen_nonces, key=self._seen_nonces.get)
            del self._seen_nonces[oldest]
        self._seen_nonces[nonce] = now
