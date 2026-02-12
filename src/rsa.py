import math
import secrets
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class RSA:
    """
    Helper for RSA key generation, certificate creation, and raw RSA signing.
    """

    def __init__(self, miller_rounds=64):
        """
        Initialize RSA helper with a configurable Miller-Rabin round count.

        Args:
            miller_rounds (int): Number of Miller-Rabin rounds for primality tests.
        """
        self._miller_rounds = miller_rounds
        self._key_path = None
        self._cert_path = None
        self._peer_cert_bytes = None

    def set_paths(self, key_path, cert_path):
        """
        Set the key and certificate paths used by rsa_sign and rsa_verify.

        Args:
            key_path (Path): Path to the PEM-encoded private key.
            cert_path (Path): Path to the PEM-encoded certificate.

        Returns:
            None
        """
        self._key_path = key_path
        self._cert_path = cert_path

    def set_peer_cert_bytes(self, peer_cert_bytes):
        """
        Store a peer certificate for signature verification.

        Args:
            peer_cert_bytes (bytes): PEM-encoded peer certificate.

        Returns:
            None
        """
        self._peer_cert_bytes = peer_cert_bytes

    def _factor_out_twos(self, n):
        """
        Factor out powers of two from n-1.

        This returns the decomposition of `n-1` as `odd * 2**exp`.

        Args:
            n (int): An integer greater than 1.

        Returns:
            tuple: A tuple `(odd, exp)` where:
                - `odd` (int): The odd part of `n-1` after removing factors of two.
                - `exp` (int): The exponent such that `n-1 = odd * 2**exp`.
        """
        x = n - 1
        e = 0
        while (x % 2 == 0):
            e += 1
            x //= 2

        return x, e

    def _miller_test(self, n):
        """
        Perform the Miller-Rabin primality test on a number.

        This function implements the Miller-Rabin probabilistic primality test algorithm
        by performing k iterations of the test. It factors n-1 as d * 2^s where d is odd,
        then tests with k random bases to determine if n is likely prime.

        Args:
            n (int): The number to test for primality (n > 2).

        Returns:
            bool: True if n is likely prime (passes all k test rounds),
                  False if n is definitely composite (fails any test round)
        """
        if (n < 2):
            return False
        if (n == 2 or n == 3):
            return True
        if (n % 2 == 0):
            return False

        d, s = self._factor_out_twos(n)
        k = self._miller_rounds

        for _ in range(k):
            # Uniform random base in [2, n-2].
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)

            if (x == 1 or x == n - 1):
                continue

            # do up to s-1 squarings
            for _ in range(s - 1):
                x = (x * x) % n
                if (x == n - 1):
                    break
                if (x == 1):
                    return False
            else:
                return False

        # passed all rounds
        return True

    def _generate_random_prime(self, k):
        """
        Generate a random k-bit probable prime using Miller-Rabin.

        Args:
            k (int): Desired bit length of the prime.

        Returns:
            int: A probable prime integer with bit-length `k`.
        """
        # Reject invalid prime sizes early.
        if k < 2:
            raise ValueError("prime bit length must be >= 2")

        while True:
            prime = secrets.randbits(k)
            prime |= (1 << (k - 1))  # force k-bit size
            prime |= 1  # force odd

            if (self._miller_test(prime)):
                return prime

    def _has_large_factor_minus_one(self, p):
        """
        Fast check that p-1 has a factor > 2**16.

        Instead of factorint(), use trial division only up to that bound.
        If the remainder > 1, it is a large factor.

        Args:
            p (int): Prime candidate to test.

        Returns:
            bool: True if p-1 has a factor larger than 2**16, False otherwise.
        """
        bound = 1 << 16  # treat factors <= bound as "small"
        m = p - 1

        # quick check for tiny primes
        for r in range(2, bound):
            while m % r == 0:
                m //= r
            if m == 1:
                return False
        return m > 1

    def _generate_rsa_key(self, k):
        """
        Generate an RSA key pair where the primes `p` and `q` each have `k` bits.

        Args:
            k (int): The bit length of the prime numbers p and q.

        Returns:
            tuple: A 5-tuple `(n, e, d, p, q)` where:
                - `n` (int): modulus `p * q`.
                - `e` (int): public exponent (default 65537 unless changed).
                - `d` (int): private exponent, inverse of `e` mod `(p-1)*(q-1)`.
                - `p`, `q` (int): the secret prime factors (each `k` bits).
        """
        min_diff = 1 << (k // 2)  # Require |p - q| > 2^{k/2}
        min_gcd = 5  # Avoid too-small gcd(p-1, q-1)
        e = 65537  # fixed large public exponent

        while True:
            p = self._generate_random_prime(k)
            q = self._generate_random_prime(k)

            if (p == q or abs(p - q) <= min_diff):
                continue

            # Guard against p-1 or q-1 being too smooth (Pollard p-1 weakness).
            if not self._has_large_factor_minus_one(p):
                continue
            if not self._has_large_factor_minus_one(q):
                continue
            # Avoid extremely small gcd(p-1, q-1).
            if math.gcd(p - 1, q - 1) < min_gcd:
                continue

            phi_n = (p - 1) * (q - 1)

            if math.gcd(e, phi_n) != 1:
                continue
            break

        n = p * q
        d = pow(e, -1, phi_n)

        return n, e, d, p, q

    def _mod_pow(self, b, d, e):
        """
        Compute (b ** d) % e using the square-and-multiply method.

        Args:
            b (int): base integer (can be larger than modulus).
            d (int): non-negative exponent.
            e (int): modulus (> 0).

        Returns:
            int: The value (b ** d) mod e. Returns 0 when e == 1.
        """
        if (e == 1):
            return 0

        result = 1
        b = b % e
        exp = d

        while (exp > 0):
            if (exp & 1):
                result = (result * b) % e
            b = (b * b) % e
            exp >>= 1
        return result

    def _crt(self, c, d, p, q):
        """
        Compute c^d mod (p*q) using the Chinese Remainder Theorem.

        Args:
            c (int): ciphertext
            d (int): private exponent
            p (int): prime p
            q (int): prime q (distinct from p)

        Returns:
            int: plaintext m = c^d mod (p*q)
        """
        # exponents mod (p-1) and (q-1)
        dp = d % (p - 1)
        dq = d % (q - 1)

        # compute m1 = c^dp mod p, m2 = c^dq mod q using mod_pow
        m1 = self._mod_pow(c % p, dp, p)
        m2 = self._mod_pow(c % q, dq, q)

        # recombine using CRT
        # compute inverse of q modulo p
        q_inv = pow(q, -1, p)

        # Garner recombination step.
        h = (q_inv * (m1 - m2)) % p
        m = (m2 + h * q) % (p * q)
        return m

    def rsa_sign(self, message):
        """
        Sign a message using RSA-CRT with a SHA-256 hash.

        This loads the private key from the path set by set_paths().

        Args:
            message (bytes): message to sign.

        Returns:
            int: signature s = H(m)^d mod (p*q).
        """
        # Require set_paths() so the private key can be loaded.
        if self._key_path is None:
            raise ValueError("rsa_sign requires set_paths() to be called first")

        # Load the private key from the configured path and extract raw RSA values.
        private_key = self._load_private_key(self._key_path)
        numbers = private_key.private_numbers()
        d = numbers.d
        p = numbers.p
        q = numbers.q
        n = p * q
        digest = hashlib.sha256(message).digest()
        h = int.from_bytes(digest, "big")

        # Raw RSA requires the hash to be smaller than the modulus.
        if h >= n:
            raise ValueError("hash out of range for modulus")
        return self._crt(h, d, p, q)

    def rsa_verify_peer(self, message, signature):
        """
        Verify an RSA signature against a message using SHA-256.

        This uses the peer certificate set by set_peer_cert_bytes().

        Args:
            message (bytes): signed message.
            signature (int): signature value.

        Returns:
            bool: True if signature is valid, False otherwise.
        """
        # Require a peer certificate for verification.
        if self._peer_cert_bytes is None:
            raise ValueError("rsa_verify_peer requires set_peer_cert_bytes() to be called first")

        cert = x509.load_pem_x509_certificate(self._peer_cert_bytes)
        numbers = cert.public_key().public_numbers()
        n = numbers.n
        e = numbers.e

        # Reject signatures outside the modulus range.
        if signature < 0 or signature >= n:
            return False
        digest = hashlib.sha256(message).digest()
        h = int.from_bytes(digest, "big")

        return self._mod_pow(signature, e, n) == h

    def _build_private_key(self, n, e, d, p, q):
        """
        Build a cryptography RSA private key from RSA parameters.

        Args:
            n (int): modulus `p * q`.
            e (int): public exponent.
            d (int): private exponent.
            p (int): prime p.
            q (int): prime q.

        Returns:
            cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey: Private key.
        """
        dp = d % (p - 1)
        dq = d % (q - 1)
        qi = pow(q, -1, p)

        public_numbers = rsa.RSAPublicNumbers(e, n)
        private_numbers = rsa.RSAPrivateNumbers(p, q, d, dp, dq, qi, public_numbers)
        return private_numbers.private_key()

    def _write_self_signed_cert(self, common_name, key, cert_path, days=365):
        """
        Write a self-signed certificate for the provided RSA key.

        Args:
            common_name (str): Common Name (CN) for the certificate subject/issuer.
            key (RSAPrivateKey): Private key used to sign the certificate.
            cert_path (Path): Output path for the PEM certificate.
            days (int): Validity period in days.
        """
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.now(timezone.utc)

        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def _write_private_key(self, key, key_path):
        """
        Write a PEM-encoded RSA private key (PKCS#1).

        Args:
            key (RSAPrivateKey): Private key to serialize.
            key_path (Path): Output path for the PEM private key.
        """
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(pem)

    def _write_ca_cert(self, common_name, key, cert_path, days=3650):
        """
        Write a self-signed CA certificate for the provided RSA key.

        Args:
            common_name (str): Common Name (CN) for the CA certificate.
            key (RSAPrivateKey): Private key used to sign the certificate.
            cert_path (Path): Output path for the PEM certificate.
            days (int): Validity period in days.
        """
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.now(timezone.utc)

        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def _load_private_key(self, key_path):
        """
        Load a PEM-encoded private key from disk.

        Args:
            key_path (Path): Path to the PEM-encoded private key file.

        Returns:
            RSAPrivateKey: Loaded private key instance.
        """
        return serialization.load_pem_private_key(key_path.read_bytes(), password=None)

    def _load_cert(self, cert_path):
        """
        Load a PEM-encoded X.509 certificate from disk.

        Args:
            cert_path (Path): Path to the PEM-encoded certificate file.

        Returns:
            x509.Certificate: Loaded certificate instance.
        """
        return x509.load_pem_x509_certificate(cert_path.read_bytes())

    def generate_ca(self, common_name, modulus_bits, cert_dir):
        """
        Generate a CA keypair and self-signed CA certificate in cert_dir.

        Args:
            common_name (str): Common Name (CN) for the CA certificate.
            modulus_bits (int): RSA modulus size in bits (must be even).
            cert_dir (Path): Output directory for CA key/cert files.

        Returns:
            tuple: `(ca_key_path, ca_cert_path)` as Path objects.
        """
        ca_key_path = cert_dir / "ca.key"
        ca_cert_path = cert_dir / "ca.crt"

        if ca_key_path.exists() and ca_cert_path.exists():
            return ca_key_path, ca_cert_path
        # Require even bit length to split into equal-size primes.
        if modulus_bits % 2 != 0:
            raise ValueError("modulus_bits must be even")

        prime_bits = modulus_bits // 2
        n, e, d, p, q = self._generate_rsa_key(prime_bits)
        key = self._build_private_key(n, e, d, p, q)
        self._write_private_key(key, ca_key_path)
        self._write_ca_cert(common_name, key, ca_cert_path)
        return ca_key_path, ca_cert_path

    def _write_ca_signed_cert(self, common_name, key, ca_key, ca_cert, cert_path, days=365):
        """
        Write a CA-signed certificate for the provided RSA key.

        Args:
            common_name (str): Common Name (CN) for the certificate.
            key (RSAPrivateKey): Private key for the subject.
            ca_key (RSAPrivateKey): CA private key used to sign.
            ca_cert (x509.Certificate): CA certificate (issuer).
            cert_path (Path): Output path for the PEM certificate.
            days (int): Validity period in days.
        """
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.now(timezone.utc)

        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def generate_ca_signed_cert(self, common_name, modulus_bits, cert_dir, ca_common_name="SecureCommunicationAppCA"):
        """
        Generate an RSA keypair and a CA-signed certificate into cert_dir.

        Args:
            common_name (str): Common Name (CN) for the certificate.
            modulus_bits (int): RSA modulus size in bits (must be even).
            cert_dir (Path): Output directory for key and cert files.
            ca_common_name (str): Common Name (CN) for the CA certificate.

        Returns:
            tuple: `(key_path, cert_path)` as Path objects.
        """
        ca_key_path, ca_cert_path = self.generate_ca(ca_common_name, 2048, cert_dir)
        ca_key = self._load_private_key(ca_key_path)
        ca_cert = self._load_cert(ca_cert_path)

        # Require even bit length to split into equal-size primes.
        if modulus_bits % 2 != 0:
            raise ValueError("modulus_bits must be even")

        prime_bits = modulus_bits // 2
        n, e, d, p, q = self._generate_rsa_key(prime_bits)
        key = self._build_private_key(n, e, d, p, q)
        key_path = cert_dir / f"{common_name}.key"
        cert_path = cert_dir / f"{common_name}.crt"
        self._write_private_key(key, key_path)
        self._write_ca_signed_cert(common_name, key, ca_key, ca_cert, cert_path)
        return key_path, cert_path
