import os
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

    def __init__(self, seed: bytes = None):
        # If no seed provided, use OS CSPRNG (Software TRNG)
        self.seed = seed if seed is not None else os.urandom(32)

    def _logistic_map(self, length: int) -> list:
        chunk_1 = int.from_bytes(self.seed[0:8], 'big')
        chunk_2 = int.from_bytes(self.seed[8:16], 'big')
        max_64 = (2**64) - 1
        x = 0.2 + (chunk_1 / max_64) * 0.6
        r = 3.9 + (chunk_2 / max_64) * 0.0999
        
        for _ in range(100): 
            x = r * x * (1.0 - x)
        seq = []
        for _ in range(length):
            x = r * x * (1.0 - x)
            seq.append(x)
        return seq

    def encrypt_payload(self, plaintext: str, receiver_pub_path: str, sender_priv_path: str):
        """Encrypts data with AES-GCM driven by chaotic maps, then signs and encapsulates."""
        # Setup Chaotic Mapping AES Key
        floats = self._logistic_map(16)
        aes_key = bytes([int(f * 255) for f in floats])
        
        cipher_aes = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext.encode('utf-8'))
      
        # RSA Signature (Authentication & Integrity)
        sender_key = RSA.import_key(open(sender_priv_path).read())
        payload_hash = SHA256.new(ciphertext + cipher_aes.nonce + tag)
        signature = pkcs1_15.new(sender_key).sign(payload_hash) 
        
        # RSA Key Encapsulation (Enables Receiver to Decrypt the Random Seed)
        receiver_pub = RSA.import_key(open(receiver_pub_path).read())
        cipher_rsa = PKCS1_OAEP.new(receiver_pub)
        enc_seed = cipher_rsa.encrypt(self.seed) 
        
        return enc_seed, signature, cipher_aes.nonce, tag, ciphertext

    def decapsulate_seed(self, enc_seed: bytes, receiver_priv_path: str) -> bytes:
        """Phase 1 of Decryption: Unlocks the CSPRNG seed."""
        receiver_priv = RSA.import_key(open(receiver_priv_path).read())
        cipher_rsa = PKCS1_OAEP.new(receiver_priv)
        self.seed = cipher_rsa.decrypt(enc_seed)
        return self.seed

    def verify_and_decrypt_payload(self, signature: bytes, nonce: bytes, tag: bytes, ciphertext: bytes, sender_pub_path: str) -> str:
        """Phase 2 of Decryption: Verifies integrity and extracts the plaintext."""
        if not self.seed:
            raise ValueError("Cryptographic seed is not initialized.")
            
        # Signature Verification
        sender_pub = RSA.import_key(open(sender_pub_path).read())
        payload_hash = SHA256.new(ciphertext + nonce + tag)
        pkcs1_15.new(sender_pub).verify(payload_hash, signature)
        
        # Reconstruct AES Key from the now-decapsulated Seed
        floats = self._logistic_map(16)
        aes_key = bytes([int(f * 255) for f in floats])
        
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_bytes = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return decrypted_bytes.decode('utf-8')