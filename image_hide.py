import numpy as np
from PIL import Image

class IWTStego: # Integer Wavelength Transform
    @staticmethod
    def _forward_iwt(img: np.ndarray):
        h, w = img.shape
        rs = (img[:, 0::2] + img[:, 1::2]) // 2
        rd = img[:, 1::2] - img[:, 0::2]
        ll = (rs[0::2, :] + rs[1::2, :]) // 2
        lh = rs[1::2, :] - rs[0::2, :]
        hl = (rd[0::2, :] + rd[1::2, :]) // 2
        hh = rd[1::2, :] - rd[0::2, :]
        return ll, lh, hl, hh

    @staticmethod
    def _inverse_iwt(ll, lh, hl, hh, shape):
        h, w = shape
        rs = np.zeros((h, w // 2), dtype=np.int32)
        rs[0::2, :], rs[1::2, :] = ll - lh // 2, lh + (ll - lh // 2)
        rd = np.zeros((h, w // 2), dtype=np.int32)
        rd[0::2, :], rd[1::2, :] = hl - hh // 2, hh + (hl - hh // 2)
        img = np.zeros((h, w), dtype=np.int32)
        img[:, 0::2], img[:, 1::2] = rs - rd // 2, rd + (rs - rd // 2)
        return np.clip(img, 0, 255).astype(np.uint8)

    def embed(self, img_path, enc_seed, signature, nonce, tag, ciphertext, crypto, output_path):
        img = Image.open(img_path).convert('L')
        img_array = np.array(img).astype(np.int32)

        img_array = np.clip(img_array, 2, 253)
        shape = img_array.shape
        
        ll, lh, hl, hh = self._forward_iwt(img_array)
        hh_flat = hh.flatten()

        # Build metadata block (516 bytes)
        meta_bytes = len(ciphertext).to_bytes(4, 'big') + enc_seed + signature
        meta_bits = []
        for b in meta_bytes:
            for i in range(8):
                meta_bits.append((b >> (7 - i)) & 1)

        # Build payload data block
        pay_bytes = nonce + tag + ciphertext
        pay_bits = []
        for b in pay_bytes:
            for i in range(8):
                pay_bits.append((b >> (7 - i)) & 1)

        # 1. Embed metadata into the first elements sequentially
        for i, bit in enumerate(meta_bits):
            hh_flat[i] = (hh_flat[i] & ~1) | bit

        # 2. Scatter payload data across remaining elements using software map
        offset = len(meta_bits)
        floats = crypto._logistic_map(len(hh_flat) - offset)
        chaotic_indices = [x + offset for x in sorted(range(len(floats)), key=lambda k: floats[k])]

        if len(pay_bits) > len(chaotic_indices):
            raise ValueError("Carrier image context size too small for target payload.")

        for bit_idx, bit in enumerate(pay_bits):
            target_pixel = chaotic_indices[bit_idx]
            hh_flat[target_pixel] = (hh_flat[target_pixel] & ~1) | bit

        hh = hh_flat.reshape(hh.shape)
        stego_array = self._inverse_iwt(ll, lh, hl, hh, shape)
        Image.fromarray(stego_array).save(output_path)

    def extract(self, img_path, crypto=None):
        img_array = np.array(Image.open(img_path).convert('L')).astype(np.int32)
        _, _, _, hh = self._forward_iwt(img_array)
        hh_flat = hh.flatten()

        def bits_to_bytes(bits):
            return bytes(int("".join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8))

        # Extract Meta Block
        meta_bits = [hh_flat[i] & 1 for i in range((4 + 256 + 256) * 8)]
        meta_bytes = bits_to_bytes(meta_bits)
        
        ct_len = int.from_bytes(meta_bytes[0:4], 'big')
        enc_seed = meta_bytes[4:260]
        signature = meta_bytes[260:516]
        
        return ct_len, enc_seed, signature, hh_flat

    def extract_chaotic_payload(self, hh_flat, ct_len, crypto):
        offset = (4 + 256 + 256) * 8
        pay_len_bits = (16 + 16 + ct_len) * 8
        
        floats = crypto._logistic_map(len(hh_flat) - offset)
        chaotic_indices = [x + offset for x in sorted(range(len(floats)), key=lambda k: floats[k])]
        
        extracted_bits = [hh_flat[chaotic_indices[i]] & 1 for i in range(pay_len_bits)]
        
        def bits_to_bytes(bits):
            return bytes(int("".join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8))
            
        pay_bytes = bits_to_bytes(extracted_bits)
        nonce = pay_bytes[0:16]
        tag = pay_bytes[16:32]
        ciphertext = pay_bytes[32:]
        return nonce, tag, ciphertext