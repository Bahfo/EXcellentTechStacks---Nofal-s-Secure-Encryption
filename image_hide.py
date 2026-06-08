import numpy as npy

from PIL import Image
from encryption import EncryptionCore

class IWTransformEngine:
    @staticmethod
    def forward_iwt_2d(img_array : npy.ndarray):
        """
        Applies a 2D Integer Wavelet Transform (Haar Lifting Scheme) to 
        an integer matrix.
        """
        img = img_array.astype(npy.int32)
        h, w = img.shape

        # Row Transformation
        row_s = (img[:, 0::2] + img[:, 1::2]) // 2
        row_d = img[:, 1::2] - img[:, 0::2]

        # Column Transformation
        ll = (row_s[0::2, :] + row_s[1::2, :]) // 2
        lh = row_s[1::2, :] - row_s[0::2, :]
        hl = (row_d[0::2, :] + row_d[1::2, :]) // 2
        hh = row_d[1::2, :] - row_d[0::2, :]
        
        return ll, lh, hl, hh

    @staticmethod
    def inverse_iwt_2d(ll, lh, hl, hh, original_shape):
        """
        Perfectly reverses the 2D IWT back to an exact integer pixel matrix.
        """
        h, w = original_shape
        
        # Reverse Column Transform
        row_s = npy.zeros((h, w // 2), dtype=npy.int32)
        row_s[0::2, :] = ll - lh // 2
        row_s[1::2, :] = lh + row_s[0::2, :]
        
        row_d = npy.zeros((h, w // 2), dtype=npy.int32)
        row_d[0::2, :] = hl - hh // 2
        row_d[1::2, :] = hh + row_d[0::2, :]
        
        # Reverse Row Transform
        img = npy.zeros((h, w), dtype=npy.int32)
        img[:, 0::2] = row_s - row_d // 2
        img[:, 1::2] = row_d + img[:, 0::2]
        
        return npy.clip(img, 0, 255).astype(npy.uint8)

    def _pack_payload(self, ciphertext: bytes, nonce: bytes, auth_tag: bytes) -> bytes:
        """Packs the cryptographic components alongside length headers into a single byte stream."""
        # Headers: 2 bytes for ciphertext length, 1 byte for nonce len, 1 byte for tag len
        header = len(ciphertext).to_bytes(2, byteorder='big') + len(nonce).to_bytes(1, byteorder='big') + len(auth_tag).to_bytes(1, byteorder='big')
        return header + ciphertext + nonce + auth_tag

    def embed_data(self, image_path: str, ciphertext: bytes, nonce: bytes, auth_tag: bytes, crypto_engine: EncryptionCore, output_path: str):
        """Embeds encrypted data bits into the HH sub-band using a chaotic path traversal."""
        img = Image.open(image_path).convert('L') # Grayscale
        img_array = npy.array(img)
        
        ll, lh, hl, hh = self.forward_iwt_2d(img_array)
        
        full_payload = self._pack_payload(ciphertext, nonce, auth_tag)
        bitstream = []
        for byte in full_payload:
            for i in range(8):
                bitstream.append((byte >> (7 - i)) & 1)
                
        total_bits = len(bitstream)
        hh_flat = hh.flatten()
        
        if total_bits > len(hh_flat):
            raise ValueError("Payload size exceeds available capacity in the high-frequency sub-band.")

        chaotic_floats = crypto_engine._generate_logistic_sequence(len(hh_flat))
        chaotic_indices = sorted(range(len(hh_flat)), key=lambda k: chaotic_floats[k])

        for bit_idx, bit_value in enumerate(bitstream):
            target_pixel_idx = chaotic_indices[bit_idx]
            hh_flat[target_pixel_idx] = (hh_flat[target_pixel_idx] & ~1) | bit_value
            
        hh = hh_flat.reshape(hh.shape)
        
        stego_array = self.inverse_iwt_2d(ll, lh, hl, hh, img_array.shape)
        Image.fromarray(stego_array).save(output_path, format="PNG")
        print(f"[SUCCESS] Stego-Image safely generated and stored at: {output_path}")

    def extract_data(self, stego_image_path: str, crypto_engine: EncryptionCore):
        """Locates, extracts, and separates payload packages directly out of the IWT frequency domain."""
        img = Image.open(stego_image_path).convert('L')
        img_array = npy.array(img)
        
        _, _, _, hh = self.forward_iwt_2d(img_array)
        hh_flat = hh.flatten()
        
        chaotic_floats = crypto_engine._generate_logistic_sequence(len(hh_flat))
        chaotic_indices = sorted(range(len(hh_flat)), key=lambda k: chaotic_floats[k])

        extracted_bits = []
        header_bit_length = 4 * 8 
        
        for i in range(header_bit_length):
            target_idx = chaotic_indices[i]
            extracted_bits.append(hh_flat[target_idx] & 1)
            
        header_bytes = bytearray()
        for i in range(0, len(extracted_bits), 8):
            byte_val = 0
            for b in range(8):
                byte_val = (byte_val << 1) | extracted_bits[i + b]
            header_bytes.append(byte_val)
            
        ct_len = int.from_bytes(header_bytes[0:2], byteorder='big')
        nonce_len = header_bytes[2]
        tag_len = header_bytes[3]
        
        total_payload_bits = (4 + ct_len + nonce_len + tag_len) * 8
        
        remaining_bits = []
        for i in range(header_bit_length, total_payload_bits):
            target_idx = chaotic_indices[i]
            remaining_bits.append(hh_flat[target_idx] & 1)
            
        all_bits = extracted_bits + remaining_bits
        payload_bytes = bytearray()
        for i in range(0, len(all_bits), 8):
            byte_val = 0
            for b in range(8):
                byte_val = (byte_val << 1) | all_bits[i + b]
            payload_bytes.append(byte_val)
            
        start = 4
        ciphertext = bytes(payload_bytes[start : start + ct_len])
        start += ct_len
        nonce = bytes(payload_bytes[start : start + nonce_len])
        start += nonce_len
        auth_tag = bytes(payload_bytes[start : start + tag_len])
        
        return ciphertext, nonce, auth_tag


if __name__ == "__main__":
    mock_hardware_key = bytes.fromhex("BC4C9DE13329512CF466EE47B5B09EE6FF39FA481055030F62A6B828B224ED8F")
    crypto = EncryptionCore(mock_hardware_key)
    sample_text = "Findings: Left lung consolidation observed. Impression: Pneumonia baseline indications."

    ct, nonce, tag = crypto.encrypt_pipeline(sample_text)
    dummy_xray_matrix = npy.random.randint(50, 200, size=(512, 512), dtype=npy.uint8)
    Image.fromarray(dummy_xray_matrix).save("test_carrier.png")

    stego_sys = IWTransformEngine()
    stego_sys.embed_data("test_carrier.png", ct, nonce, tag, crypto, "stego_output.png")

    ex_ct, ex_nonce, ex_tag = stego_sys.extract_data("stego_output.png", crypto)
    restored_report = crypto.decrypt_pipeline(ex_ct, ex_nonce, ex_tag)

    print(f"\nHidden Message Recovered out of Frequency Domain:\n-> {restored_report}")