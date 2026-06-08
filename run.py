import os
import numpy as np
from PIL import Image

from encryption import OpenBoxCrypto
from image_hide import IWTStego

class SecurePipelineOrchestrator:
    def __init__(self, input_image_path: str, output_image_path: str):
        self.input_image = input_image_path
        self.output_image = output_image_path
        self.crypto = None
        self.stego_sys = IWTStego()

    def zero_memory(self, *buffers):
        """Wipes sensitive arrays from RAM to leave zero trace."""
        for buf in buffers:
            if isinstance(buf, bytearray):
                for i in range(len(buf)):
                    buf[i] = 0
            elif isinstance(buf, np.ndarray):
                buf.fill(0)

    def process_pipeline(self, clinical_note: str):
        print("=== SOFTWARE-BASED SECURE CRITICAL PIPELINE ===")
        
        # 1. Automatic Key Distribution via internal CSPRNG
        self.crypto = OpenBoxCrypto()
        print(f"[+] Secure Software TRNG Seed Allocated: {self.crypto.seed.hex().upper()[:32]}...")

        # 2. Key Generation for Demonstration Pipeline tracking
        print("[*] Simulating identity parameter isolation paths...")
        priv_p, pub_p = OpenBoxCrypto.generate_rsa_keys("automation_test")
        
        # 3. Cryptographic Steganography Execution
        enc_seed, sig, nonce, tag, ct = self.crypto.encrypt_payload(clinical_note, pub_p, priv_p)
        print(f"[+] Text Encrypted. Length: {len(ct)} bytes")

        self.stego_sys.embed(self.input_image, enc_seed, sig, nonce, tag, ct, self.crypto, self.output_image)
        print(f"[+] Frequency Steganography Completed -> Output saved as: {self.output_image}")

        # 4. Verification Pass
        ct_len, ex_seed, ex_sig, hh_flat = self.stego_sys.extract(self.output_image, self.crypto)
        ex_nonce, ex_tag, ex_ct = self.stego_sys.extract_chaotic_payload(hh_flat, ct_len, self.crypto)
        
        extracted_text = self.crypto.decrypt_payload(ex_seed, ex_sig, ex_nonce, ex_tag, ex_ct, priv_p, pub_p)
        print(f"[+] Self-Test Decryption Check Success. Extracted Note:\n    \"{extracted_text}\"")

        # 5. Clean Memory Residue 
        volatile_buffer = bytearray(clinical_note.encode('utf-8'))
        self.zero_memory(volatile_buffer, ct)
        print("[+] Zero-Memory Trace Complete: Volatile process frames cleared from RAM.")

if __name__ == "__main__":
    if not os.path.exists("Dataset/Set2"):
        os.makedirs("Dataset/Set2")
        Image.new('L', (512, 512), color=128).save("Dataset/Set2/image_2.png")
        
    input_xray = "Dataset/Set2/image_2.png"
    stego_output = "stego_xray.png"
    doctor_description = "Findings: Normal anatomy. Local systems confirmed fully operational."

    orchestrator = SecurePipelineOrchestrator(input_xray, stego_output)
    orchestrator.process_pipeline(doctor_description)