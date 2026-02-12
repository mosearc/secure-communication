import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class AES_GCM:
    """
    Algorithm: AES-256-GCM
    Message Format: SeqNum || IV || Ciphertext || AuthTag
    Security Features:
    - Confidentiality (AES)
    - Integrity & Authenticity (GCM Tag)
    - Replay & Reordering Protection (Monotonic Sequence Number as AAD)
    """

    def __init__(self, session_key):
        """
        Initialize the secure channel with a derived shared secret.

        Args:
            session_key (bytes): A 32-byte (256-bit) shared secret derived from the
                key exchange.

        Raises:
            ValueError: If the session key is not exactly 32 bytes.
        """
        if len(session_key) != 32:
            raise ValueError("Session key must be 32 bytes for AES-256.")

        self.session_key = session_key

        # State for Replay Protection
        self.send_seq_num = 0
        self.recv_seq_num = 0

        self.SEQ_SIZE = 8
        self.IV_SIZE = 12
        self.TAG_SIZE = 16

    def enc(self, plaintext):
        """
        Encrypts a message using AES-GCM and constructs the packet.

        Args:
            plaintext (bytes | str): Data to encrypt.

        Returns:
            bytes: Packet containing SeqNum || IV || Ciphertext || AuthTag.
        """
        if not isinstance(plaintext, bytes):
            plaintext = plaintext.encode()

        self.send_seq_num += 1

        # Serialize Sequence Number (Big Endian)
        seq_bytes = struct.pack('>Q', self.send_seq_num)

        # Generate IV Nonce
        iv = get_random_bytes(self.IV_SIZE)

        cipher = AES.new(self.session_key, AES.MODE_GCM, nonce=iv)

        # Add Sequence Number as Additional Authenticated Data (AAD)
        cipher.update(seq_bytes)

        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        packet = seq_bytes + iv + ciphertext + tag

        return packet

    def dec(self, packet):
        """
        Decrypts a packet and verifies integrity.

        Args:
            packet (bytes): Packet containing SeqNum || IV || Ciphertext || AuthTag.

        Returns:
            bytes: Decrypted plaintext.

        Raises:
            ValueError: If the packet is malformed, replayed, or fails tag validation.
        """
        # Length Check
        min_length = self.SEQ_SIZE + self.IV_SIZE + self.TAG_SIZE
        if len(packet) < min_length:
            raise ValueError("Packet is too short to be valid.")

        # Parsing: SeqNum || IV || Ciphertext || AuthTag
        seq_bytes = packet[:self.SEQ_SIZE]
        iv = packet[self.SEQ_SIZE: self.SEQ_SIZE + self.IV_SIZE]

        ciphertext = packet[self.SEQ_SIZE + self.IV_SIZE: -self.TAG_SIZE]
        tag = packet[-self.TAG_SIZE:]

        # replay and Reordering Check
        received_seq = struct.unpack('>Q', seq_bytes)[0]

        if received_seq <= self.recv_seq_num:
            # PROBLEM: Message is old or duplicated
            raise ValueError(f"Replay detected! Received Seq {received_seq} <= Last Seen {self.recv_seq_num}")

        cipher = AES.new(self.session_key, AES.MODE_GCM, nonce=iv)

        # Verify Sequence Number
        cipher.update(seq_bytes)

        # Decrypt and Verify Tag
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise ValueError("Integrity check failed: Invalid Authentication Tag.")

        # Update State
        self.recv_seq_num = received_seq

        return plaintext
