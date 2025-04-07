import os
import sys
import yaml
import traceback
from datetime import datetime
import time
import secrets

def load_config():
    """Load configuration from the YAML file."""
    try:
        with open("main_config.yaml", "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Failed to load configuration: {str(e)}")
        sys.exit(1)

def main():
    """Main function to initialize and run the software."""
    try:
        # Initialize Qt application FIRST before any other Qt-related operations
        from PyQt6.QtWidgets import QApplication
        app = QApplication(sys.argv)

        # Add the project root directory to the Python path
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))

        # Load configuration
        config = load_config()

        # Initialize Error Manager first (non-Qt component)
        from CORE_FORENSICS.error_management import ErrorManager, ErrorSeverity
        error_manager = ErrorManager(config["global"]["logs_directory"])

        # Initialize all non-UI components
        # AI/ML modules
        from AI_ML.ml_utils import MLUtils
        from AI_ML.ai_analyzer import AIAnalyzer
        ml_utils = MLUtils(error_manager)
        ai_analyzer = AIAnalyzer(error_manager, config)

        # Blockchain modules
        from BLOCKCHAIN.hyperledger_manager1 import HyperledgerManager
        from BLOCKCHAIN.evidence_validator import EvidenceValidator
        from BLOCKCHAIN.ipfs_manager import IPFSManager
        from BLOCKCHAIN.security_manager import SecurityManager
        hyperledger_manager = HyperledgerManager(config["blockchain"]["config_path"])
        evidence_validator = EvidenceValidator(hyperledger_manager)
        ipfs_manager = IPFSManager(config["blockchain"]["ipfs_storage_directory"])
        security_manager = SecurityManager()

        # Core Forensics modules
        os.makedirs(config["core_forensics"]["recovered_files_directory"], exist_ok=True)
        from CORE_FORENSICS.audit_manager import AuditManager
        from CORE_FORENSICS.core_manager import CoreManager
        from CORE_FORENSICS.database_manager import ForensicDatabaseManager
        from CORE_FORENSICS.disk_acquisition_manager import DiskAcquisitionManager
        from CORE_FORENSICS.distributed_manager import DistributedManager
        from CORE_FORENSICS.file_recovery_engine_2 import FileRecoveryEngine
        from CORE_FORENSICS.filesystem_analyzer import FilesystemAnalyzer
        
        audit_manager = AuditManager(config["core_forensics"]["audit_logs_directory"])
        case_id = f"{int(time.time())}_{secrets.token_hex(2)}"
        core_manager = CoreManager(
        components=[
            'audit_manager', 'database_manager', 'disk_acquisition',
            'file_recovery', 'filesystem_analyzer', 'distributed_manager'
        ],
        case_id=case_id 
        )
        disk_acquisition_manager = DiskAcquisitionManager(
            os.path.join(config["core_forensics"]["recovered_files_directory"], "disk_images"),
            case_id=case_id
        )
        distributed_manager = DistributedManager()
        file_recovery_engine = FileRecoveryEngine(config["core_forensics"]["recovered_files_directory"])
        filesystem_analyzer = FilesystemAnalyzer(config["core_forensics"]["root_path"])

        # Initialize and show login window first
        from UI.login_window import LoginWindow
        login_window = LoginWindow()
        login_window.show()

        # Start the Qt event loop
        sys.exit(app.exec())

    except Exception as e:
        if 'error_manager' in locals():
            error_manager._log_error({
                'component': 'main',
                'error_type': type(e).__name__,
                'category': 'initialization',
                'message': str(e),
                'severity': 'CRITICAL',
                'stack_trace': traceback.format_exc()
            }, ErrorSeverity.CRITICAL)
        print(f"Application failed to start: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
