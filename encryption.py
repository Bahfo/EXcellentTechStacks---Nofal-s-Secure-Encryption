import os
from Crypto.Cipher import AES


class EncryptionCore:
    def __init__(self, hardware_seed : bytes):
        if len(hardware_seed) != 32:
            raise ValueError("SEED ERROR: Hardware seed must be exactly 32 bytes!")
        self.hardware_seed = hardware_seed
        self.x0, self.r = self._device_chaotic_parameters()

    def _device_chaotic_parameters(self):
        """
        Derives highly precise chaotic parameters from hardware seed.
        """
        chunk_1 = int.from_bytes(self.hardware_seed[0:8], byteorder='big')
        chunk_2 = int.from_bytes(self.hardware_seed[8:16], byteorder='big')

        # Maximum value of eight bytes to normalize floats

        # Scaling x0 and r to be between 0.2 and 0.8, and 3.9 and 3.99999 respectively
        max_64bit = (2**64) - 1
        x0 = 0.2 + (chunk_1 / max_64bit) * 0.6
        r = 3.9 + (chunk_2 / max_64bit) * 0.0999

        return x0, r

    def _generate_logistic_sequence(self, length: int):
        """
        Generates a sequence of chaotic floats based on the Logistic Map equation.
        """
        sequence = []
        x = self.x0

        for _ in range(100):
            x = self.r * x * (1.0 - x)

        for _ in range(length):
            x = self.r * x * (1.0 - x)
            sequence.append(x)

        return sequence

    def permute_bytes(self, data: bytes) -> bytes:
        """
        Permutes (scrambles) the order of bytes using the chaotic index mapping.
        """
        n = len(data)
        if n <= 1:
            return data
            
        chaotic_floats = self._generate_logistic_sequence(n)
        
        # Create list of indices sorted by their corresponding chaotic value
        permutation_vector = sorted(range(n), key=lambda k: chaotic_floats[k])
        
        # Re-map bytes to indices
        scrambled = bytearray(n)
        for original_idx, target_idx in enumerate(permutation_vector):
            scrambled[target_idx] = data[original_idx]
            
        return bytes(scrambled)

    def unpermute_bytes(self, scrambled_data: bytes) -> bytes:
        """
        Perfectly reverses the chaotic permutation to restore original byte order.
        """
        n = len(scrambled_data)
        if n <= 1:
            return scrambled_data
            
        chaotic_floats = self._generate_logistic_sequence(n)
        permutation_vector = sorted(range(n), key=lambda k: chaotic_floats[k])
        
        # Reverse structural mapping layout
        original = bytearray(n)
        for original_idx, target_idx in enumerate(permutation_vector):
            original[original_idx] = scrambled_data[target_idx]
            
        return bytes(original)

    def encrypt_pipeline(self, plaintext: str) -> tuple[bytes, bytes, bytes]:
        """Runs Full Encryption: Text -> Chaos Permutation -> AES-256-GCM."""
        raw_bytes = plaintext.encode('utf-8')
        permuted_bytes = self.permute_bytes(raw_bytes)
        aes_key = self.hardware_seed 
        cipher = AES.new(aes_key, AES.MODE_GCM)
        
        ciphertext, auth_tag = cipher.encrypt_and_digest(permuted_bytes)
        nonce = cipher.nonce
        return ciphertext, nonce, auth_tag

    def decrypt_pipeline(self, ciphertext: bytes, nonce: bytes, auth_tag: bytes) -> str:
        """Runs Full Decryption: AES Decrypt -> Verification -> Inverse Chaos Permutation."""
        aes_key = self.hardware_seed
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        permuted_bytes = cipher.decrypt_and_verify(ciphertext, auth_tag)
        original_bytes = self.unpermute_bytes(permuted_bytes)
        
        return original_bytes.decode('utf-8')


if __name__ == "__main__":
    mock_hardware_key = bytes.fromhex("BC4C9DE13329512CF466EE47B5B09EE6FF39FA481055030F62A6B828B224ED8F")
    
    sample_report = "Findings: Lungs are clear. Impression: No acute abnormalities."
    print(f"Original Text: {sample_report}\n")
    
    engine = EncryptionCore(mock_hardware_key)
    
    ct, nonce, tag = engine.encrypt_pipeline(sample_report)
    print(f"Encrypted Ciphertext (Hex): {ct.hex().upper()[:60]}...")
    print(f"AES Nonce (Hex): {nonce.hex().upper()}")
    print(f"Auth Tag (Hex): {tag.hex().upper()}\n")
    
    decrypted_text = engine.decrypt_pipeline(ct, nonce, tag)
    print(f"Perfect Reconstruction Check: {decrypted_text}")