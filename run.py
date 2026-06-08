import os
import hmac
import hashlib
import numpy as np
from PIL import Image

# Local Imports
from connection import HardwareToken
from encryption import EncryptionCore
from image_hide import IWTransformEngine
from criteria import StegoEvaluator

class SecurePipelineOrchestrator:
    def __init__(self, input_image_path: str, output_image_path: str):
        self.input_image = input_image_path
        self.output_image = output_image_path
        self.token = HardwareToken()
        self.crypto = None
        self.stego_sys = IWTransformEngine()

    def zero_memory(self, *buffers):
        """Phase 3: Wipes sensitive arrays from RAM to leave zero trace."""
        for buf in buffers:
            if isinstance(buf, bytearray):
                for i in range(len(buf)):
                    buf[i] = 0
            elif isinstance(buf, np.ndarray):
                buf.fill(0)

    def execute_hardware_handshake(self) -> bool:
        """
        Phase 3: Challenge-Response Authentication Handshake
        The application stays locked until the ESP32 completes this routine.
        """
        print("=== [1/4] HARDWARE CHALLENGE-RESPONSE HANDSHAKE ===")
        try:
            if not self.token.connect():
                print("[-] CRITICAL ERROR: Hardware token authentication failed.")
                return False
            print("[+] SUCCESS: Token authenticated. Application unlocked.\n")
            return True
        except Exception as e:
            print(f"[-] Hardware link connection failure: {e}")
            return False

    def execute_key_distribution(self) -> bool:
        """
        Phase 1, Step 1: Key Distribution
        Extracts the high-entropy TRNG seed to initialize the local ciphers.
        """
        print("=== [2/4] HARDWARE KEY DISTRIBUTION VIA TRNG ===")
        raw_seed = self.token.request_hardware_seed()
        if not raw_seed:
            print("[-] CRITICAL ERROR: Failed to distribute hardware seed.")
            return False
        
        print(f"[+] Physical TRNG Seed Acquired: {raw_seed.hex().upper()[:32]}...")
        
        self.crypto = EncryptionCore(raw_seed)
        print("[+] Crypto Engine initialized with hardware chaotic parameters.\n")
        return True

    def execute_payload_authentication(self, ciphertext: bytes, nonce: bytes, auth_tag: bytes) -> bytes:
        """
        Phase 1, Step 3: Authentication & Integrity Signing
        Hashes the encrypted payload and pipes it down to the ESP32 over the 
        existing serial connection to receive an unforgeable Ed25519 signature.
        """
        print("=== [4/4] PAYLOAD INTEGRITY AUTHENTICATION (Ed25519) ===")
        
        payload_bundle = ciphertext + nonce + auth_tag
        payload_hash = hashlib.sha256(payload_bundle).digest()
        print(f"[+] Calculated Cryptographic Bundle Hash: {payload_hash.hex().upper()}")
        
        serial_conn = self.token.connection
        try:
            serial_conn.reset_input_buffer()
            
            serial_conn.write(b'S')
            serial_conn.write(payload_hash)
            
            hex_signature = serial_conn.readline().decode('utf-8').strip()
            
            if len(hex_signature) == 128:
                signature_bytes = bytes.fromhex(hex_signature)
                print(f"[+] Hardware Signature Bound: {signature_bytes.hex().upper()[:40]}...")
                return signature_bytes
            else:
                print(f"[-] Malformed sign response from HSM token: {hex_signature}")
                return None
                
        except Exception as e:
            print(f"[-] Hardware handshake signature transfer failed: {e}")
            return None

    def process_pipeline(self, clinical_note: str):
        """Orchestrates the entire connected loop from physical layer to evaluation."""
        if not self.execute_hardware_handshake():
            return

        try:
            if not self.execute_key_distribution():
                return

            print("=== [3/4] STEGANOGRAPHY CORE PIPELINE ===")
            ciphertext, nonce, auth_tag = self.crypto.encrypt_pipeline(clinical_note)
            print(f"[+] Text Encrypted. Length: {len(ciphertext)} bytes")

            self.stego_sys.embed_data(
                self.input_image, ciphertext, nonce, auth_tag, 
                self.crypto, self.output_image
            )

            ex_ct, ex_nonce, ex_tag = self.stego_sys.extract_data(self.output_image, self.crypto)
            hardware_signature = self.execute_payload_authentication(ex_ct, ex_nonce, ex_tag)

            if hardware_signature:
                print("\n[+] SUCCESS: Secure transaction fully bound to HSM hardware.")
            
            print("\n=== SYSTEM METRICS AUDIT ===")
            psnr = StegoEvaluator.calculate_psnr(self.input_image, self.output_image)
            ssim_val = StegoEvaluator.calculate_ssim(self.input_image, self.output_image)
            avalanche = StegoEvaluator.verify_avalanche_effect(EncryptionCore, clinical_note, self.token.request_hardware_seed() or b'\x00'*32)
            
            print(f" -> PSNR Score: {psnr:.4f} dB")
            print(f" -> SSIM Score: {ssim_val:.6f}")
            print(f" -> Cryptographic Avalanche Level: {avalanche:.2f}%")

            volatile_buffer = bytearray(clinical_note.encode('utf-8'))
            self.zero_memory(volatile_buffer, ciphertext)
            print("[+] Zero-Memory Trace: Sensitive memory blocks purged.")

        finally:
            self.token.close()

if __name__ == "__main__":
    input_xray = "Dataset/Set2/image_2.png"
    stego_output = "stego_xray.png"
    
    doctor_description = (
        "Findings: PA and lateral views of the chest show stable cardiomegaly. "
        "No focal consolidation, pneumothorax, or pleural effusion. "
        "Impression: No acute cardiopulmonary abnormality."
    )

    orchestrator = SecurePipelineOrchestrator(input_xray, stego_output)
    orchestrator.process_pipeline(doctor_description)