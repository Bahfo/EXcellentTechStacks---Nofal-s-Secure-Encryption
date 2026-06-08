import os
import numpy as np
from PIL import Image
from encryption import EncryptionCore
from image_hide import IWTransformEngine

def run_real_image_test(input_image_path, output_image_path):
    if not os.path.exists(input_image_path):
        print(f"ERROR: Could not find '{input_image_path}'. Please place a valid image in the folder.")
        return

    print("--- STEP 1: INITIALIZING HARDWARE KEY & CRYPTO ---")
    hardware_key = bytes.fromhex("BC4C9DE13329512CF466EE47B5B09EE6FF39FA481055030F62A6B828B224ED8F")
    crypto = EncryptionCore(hardware_key)
    
    clinical_report = (
        "Findings: PA and lateral views of the chest show stable cardiomegaly. "
        "No focal consolidation, pneumothorax, or pleural effusion. "
        "Impression: No acute cardiopulmonary abnormality."
    )
    print(f"Clinical Report to Hide:\n-> '{clinical_report}'\n")

    ciphertext, nonce, auth_tag = crypto.encrypt_pipeline(clinical_report)
    print(f"Encrypted Ciphertext Length: {len(ciphertext)} bytes")
    print(f"AES Nonce: {nonce.hex().upper()}")
    print(f"Auth Tag: {auth_tag.hex().upper()}\n")

    print("--- STEP 2: EMBEDDING INTO IMAGE FREQUENCY DOMAIN ---")
    stego_sys = IWTransformEngine()
    
    stego_sys.embed_data(input_image_path, ciphertext, nonce, auth_tag, crypto, output_image_path)
    
    print("\n--- STEP 3: REVERSE EXTRACTION & VALIDATION ---")
    ex_ciphertext, ex_nonce, ex_tag = stego_sys.extract_data(output_image_path, crypto)
    
    restored_report = crypto.decrypt_pipeline(ex_ciphertext, ex_nonce, ex_tag)
    
    print("\nHidden Message Recovered Successfully:")
    print(f"-> '{restored_report}'\n")

    if restored_report == clinical_report:
        print("[STATUS] SUCCESS: The data is 100% intact and uncorrupted!")
        
        orig_pixels = np.array(Image.open(input_image_path).convert('L'))
        stego_pixels = np.array(Image.open(output_image_path).convert('L'))
        pixel_diff = np.sum(orig_pixels != stego_pixels)
        total_pixels = orig_pixels.size
        print(f"[STATUS] Integrity Stats: Altered just {pixel_diff} out of {total_pixels} total pixels.")
    else:
        print("[STATUS] FAILURE: Decrypted text does not match the original report.")

if __name__ == "__main__":
    run_real_image_test("Dataset/Set2/image_2.png", "stego_xray.png")