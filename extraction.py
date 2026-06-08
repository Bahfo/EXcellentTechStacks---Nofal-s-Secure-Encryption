import os
import csv
import shutil

CSV_REPORTS_PATH = 'data_source/indiana_reports.csv'
CSV_PROJECTIONS_PATH = 'data_source/indiana_projections.csv'
IMAGES_DIR = 'data_source/images/images_normalized'
OUTPUT_DIR = 'data_source/Dataset'

def extract_clean_pairs(num_pairs=10):
    print("Parsing clinical reports natively...")
    reports = {}
    
    with open(CSV_REPORTS_PATH, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            uid = row['uid']
            findings = row.get('findings', '').strip()
            impression = row.get('impression', '').strip()
            
            full_text = f"Findings: {findings}\nImpression: {impression}"
            
            if findings or impression:
                reports[uid] = full_text

    print("Mapping projections to localized image matrices...")
    pairs_extracted = 0
    
    with open(CSV_PROJECTIONS_PATH, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if pairs_extracted >= num_pairs:
                break
                
            uid = row['uid']
            filename = row['filename']
            source_image_path = os.path.join(IMAGES_DIR, filename)
            
            if uid in reports and os.path.exists(source_image_path):
                report_text = reports[uid]
                
                if "XXXX" in report_text and len(report_text.replace("XXXX", "").strip()) < 30:
                    continue 
                
                pairs_extracted += 1
                
                set_folder = os.path.join(OUTPUT_DIR, f"Set{pairs_extracted}")
                os.makedirs(set_folder, exist_ok=True)
                
                ext = os.path.splitext(filename)[1]
                target_image_name = f"image_{pairs_extracted}{ext}"
                
                target_image_path = os.path.join(set_folder, target_image_name)
                target_text_path = os.path.join(set_folder, f"text_{pairs_extracted}.txt")
                
                shutil.copy(source_image_path, target_image_path)
                
                with open(target_text_path, mode='w', encoding='utf-8') as txt_file:
                    txt_file.write(report_text)
                    
                print(f" -> Constructed Set{pairs_extracted} inside '{set_folder}'")
                
                del reports[uid]

if __name__ == "__main__":
    extract_clean_pairs(10)
    print("\nExtraction pipeline completed successfully.")