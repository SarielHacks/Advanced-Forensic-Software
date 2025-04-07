import os
from pathlib import Path
import yaml

def verify_directories():
    with open('main_config.yaml') as f:
        config = yaml.safe_load(f)
    
    required_dirs = [
        config['ai_ml']['data_directory'],
        config['ai_ml']['logs_directory'],
        config['blockchain']['ipfs_storage_directory'],
        config['core_forensics']['evidence_directory'],
        config['core_forensics']['error_log_directory'],
        config['core_forensics']['recovered_files_directory'],
        config['ui']['assets_directory']
    ]
    
    for dir_path in required_dirs:
        path = Path(dir_path)
        try:
            path.mkdir(parents=True, exist_ok=True)
            print(f"Verified: {path}")
        except Exception as e:
            print(f"Error creating {path}: {e}")

if __name__ == "__main__":
    verify_directories()
