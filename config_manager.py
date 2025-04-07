# config_manager.py
import yaml
import os

_config = None

def load_config():
    global _config
    try:
        config_path = "/home/sariel/Desktop/Automated_Forensics_Software/main_config.yaml"
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found at: {config_path}")
        with open(config_path, "r") as f:
            _config = yaml.safe_load(f)
        return _config
    except Exception as e:
        raise RuntimeError(f"Failed to load configuration: {str(e)}")

def get_config():
    """Get the configuration (loads if not already loaded)"""
    return _config or load_config()
