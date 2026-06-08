from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

class OpenBoxCrypto:
    @staticmethod
    def generate_rsa_keys(output_prefix="user"):
        """Generates standard RSA-2048 keypairs for identities."""
        key = RSA.generate(2048)
        with open(f"{output_prefix}_private.pem", "wb") as f:
            f.write(key.export_key())
        with open(f"{output_prefix}_public.pem", "wb") as f:
            f.write(key.publickey().export_key())
        return f"{output_prefix}_private.pem", f"{output_prefix}_public.pem"

    def __init__(self, hardware_seed: bytes = None):
        self.seed = hardware_seed

    def _logistic_map(self, length: int) -> list:
        chunk_1 = int.from_bytes(self.seed[0:8], 'big')
        chunk_2 = int.from_bytes(self.seed[8:16], 'big')
        max_64 = (2**64) - 1
        x = 0.2 + (chunk_1 / max_64) * 0.6
        r = 3.9 + (chunk_2 / max_64) * 0.0999
        
        for _ in range(100): x = r * x * (1.0 - x)
        seq = []
        for _ in range(length):
            x = r * x * (1.0 - x)
            seq.append(x)
        return seq

    def permute(self, data: bytes, reverse=False) -> bytes:
        n = len(data)
        if n <= 1: return data
        floats = self._logistic_map(n)
        indices = sorted(range(n), key=lambda k: floats[k])
        
        out = bytearray(n)
        for i, target in enumerate(indices):
            if reverse: out[i] = data[target]
            else: out[target] = data[i]
        return bytes(out)

    def encrypt_payload(self, plaintext: str, receiver_pub_path: str, 
            sender_priv_path: str) -> tuple:
        """Encrypts payload and encapsulates seed via RSA."""
        # AES Encryption (Confidentiality)
        raw_bytes = plaintext.encode('utf-8')
        scrambled = self.permute(raw_bytes)
        cipher_aes = AES.new(self.seed, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(scrambled)
        
        # RSA Signature (Authentication & Integrity)
        sender_key = RSA.import_key(open(sender_priv_path).read())
        payload_hash = SHA256.new(ciphertext + cipher_aes.nonce + tag)
        signature = pkcs1_15.new(sender_key).sign(payload_hash) # 256 bytes
        
        # RSA Key Encapsulation (Distribution)
        receiver_pub = RSA.import_key(open(receiver_pub_path).read())
        cipher_rsa = PKCS1_OAEP.new(receiver_pub)
        enc_seed = cipher_rsa.encrypt(self.seed) # 256 bytes
        
        return enc_seed, signature, cipher_aes.nonce, tag, ciphertext

    def decrypt_payload(self, enc_seed, signature, nonce, tag, ciphertext, 
            receiver_priv_path, sender_pub_path) -> str:
        """Decapsulates seed, verifies identity, and decrypts."""
        # RSA Seed Decapsulation
        receiver_priv = RSA.import_key(open(receiver_priv_path).read())
        cipher_rsa = PKCS1_OAEP.new(receiver_priv)
        self.seed = cipher_rsa.decrypt(enc_seed)
        
        # Signature Verification
        sender_pub = RSA.import_key(open(sender_pub_path).read())
        payload_hash = SHA256.new(ciphertext + nonce + tag)

        # Raises error if tampered
        pkcs1_15.new(sender_pub).verify(payload_hash, signature)
        
        # AES Decryption
        cipher_aes = AES.new(self.seed, AES.MODE_GCM, nonce=nonce)
        scrambled = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return self.permute(scrambled, reverse=True).decode('utf-8')