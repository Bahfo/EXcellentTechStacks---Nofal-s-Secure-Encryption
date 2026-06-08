import numpy as np
from PIL import Image
from skimage.metrics import structural_similarity as ssim

class StegoEvaluator:
    @staticmethod
    def calculate_psnr(original_path: str, stego_path: str) -> float:
        """Calculates Peak Signal-to-Noise Ratio (PSNR) between original and stego images."""
        img1 = np.array(Image.open(original_path).convert('L')).astype(np.float64)
        img2 = np.array(Image.open(stego_path).convert('L')).astype(np.float64)
        
        mse = np.mean((img1 - img2) ** 2)
        if mse == 0:
            return float('inf')
            
        max_pixel = 255.0
        psnr = 20 * np.log10(max_pixel / np.sqrt(mse))
        return psnr

    @staticmethod
    def calculate_ssim(original_path: str, stego_path: str) -> float:
        """Calculates the Structural Similarity Index (SSIM) matching structural changes."""
        img1 = np.array(Image.open(original_path).convert('L'))
        img2 = np.array(Image.open(stego_path).convert('L'))
        
        score, _ = ssim(img1, img2, full=True)
        return score

    @staticmethod
    def verify_avalanche_effect(crypto_engine_class, sample_text: str, hardware_key: bytes):
        """Measures the Avalanche Effect bit-variance changes on a single character modification."""
        engine1 = crypto_engine_class(hardware_key)
        ct1, _, _ = engine1.encrypt_pipeline(sample_text)
        
        modified_text = sample_text[:-1] + "!"
        engine2 = crypto_engine_class(hardware_key)
        ct2, _, _ = engine2.encrypt_pipeline(modified_text)
        
        total_bits = min(len(ct1), len(ct2)) * 8
        bit_differences = 0
        
        for b1, b2 in zip(ct1, ct2):
            bit_differences += bin(b1 ^ b2).count("1")
            
        avalanche_percentage = (bit_differences / total_bits) * 100
        return avalanche_percentage

if __name__ == "__main__":
    import os
    from encryption import EncryptionCore 
    
    orig = "Dataset/Set2/image_2.png"
    stego = "stego_xray.png"
    
    if os.path.exists(orig) and os.path.exists(stego):
        print("=== STAGE 4: RUNNING METRIC EVALUATIONS ===")
        
        # 1. PSNR Metric Run
        psnr_score = StegoEvaluator.calculate_psnr(orig, stego)
        print(f"Calculated PSNR : {psnr_score:.4f} dB " + ("(EXCELLENT > 40dB)" if psnr_score > 40 else "(CONCERNING)"))
        
        # 2. SSIM Metric Run
        ssim_score = StegoEvaluator.calculate_ssim(orig, stego)
        print(f"Calculated SSIM : {ssim_score:.6f} " + ("(EXCELLENT > 0.99)" if ssim_score > 0.99 else "(CONCERNING)"))
        
        # 3. Avalanche Effect Verification
        key = bytes.fromhex("BC4C9DE13329512CF466EE47B5B09EE6FF39FA481055030F62A6B828B224ED8F")
        text = "Findings: PA and lateral views of the chest show stable cardiomegaly."
        av_score = StegoEvaluator.verify_avalanche_effect(EncryptionCore, text, key)
        print(f"Avalanche Effect: {av_score:.2f}% bit flipping (Target: ~50% for ideal chaos/diffusion)")