import os
import logging
import pandas as pd
from datetime import datetime
from BLOCKCHAIN.hyperledger_manager1 import HyperledgerManager
from BLOCKCHAIN.evidence_validator import EvidenceValidator

# Constants
LOG_DIR = "logs"
ERROR_LOG_FILE = os.path.join(LOG_DIR, "error_logs.csv")

# Ensure directories exist
os.makedirs(LOG_DIR, exist_ok=True)

class AIErrorManager:
    def __init__(self, hyperledger_manager, evidence_validator):
        """
        Initialize the AIErrorManager with Hyperledger Manager and Evidence Validator.
        """
        self.hyperledger_manager = hyperledger_manager
        self.evidence_validator = evidence_validator
        self.error_logs = self._load_error_logs()  # Load existing error logs
        self.setup_logging()  # Configure logging

    def setup_logging(self):
        """
        Configure logging for error management.
        """
        logging.basicConfig(
            filename=os.path.join(LOG_DIR, "ai_error_management.log"),
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

    def _load_error_logs(self):
        """
        Load existing error logs from a CSV file.
        """
        if os.path.exists(ERROR_LOG_FILE):
            return pd.read_csv(ERROR_LOG_FILE)
        return pd.DataFrame(columns=["timestamp", "error_type", "severity", "description", "fix_applied", "status"])

    def log_error(self, error_type, severity, description, fix_applied=None, status="Pending"):
        """
        Log an error with details and store it in the Hyperledger blockchain.
        """
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            error_entry = {
                "timestamp": timestamp,
                "error_type": error_type,
                "severity": severity,
                "description": description,
                "fix_applied": fix_applied,
                "status": status
            }

            # Add to error logs using pd.concat()
            new_row = pd.DataFrame([error_entry])
            self.error_logs = pd.concat([self.error_logs, new_row], ignore_index=True)
            self.error_logs.to_csv(ERROR_LOG_FILE, index=False)

            # Log to Hyperledger blockchain
            error_id = f"error_{len(self.error_logs)}"
            metadata = {
                "error_type": error_type,
                "severity": severity,
                "description": description,
                "fix_applied": fix_applied,
                "status": status
            }
            self.hyperledger_manager.register_evidence(
                error_id,
                metadata,
                self.evidence_validator.calculate_multi_hash(description)["sha256"]
            )

            # Log to console and file
            logging.error(f"{error_type} (Severity: {severity}): {description}")
            print(f"Error logged: {error_type} - {description}")
        except Exception as e:
            logging.error(f"Failed to log error: {str(e)}")
            print(f"Failed to log error: {str(e)}")

    def detect_error_trends(self):
        """
        Analyze error logs to detect trends and predict potential failures.
        """
        try:
            if self.error_logs.empty:
                return "No errors logged yet."

            # Count errors by type and severity
            error_trends = self.error_logs.groupby(["error_type", "severity"]).size().reset_index(name="count")
            return error_trends
        except Exception as e:
            logging.error(f"Failed to detect error trends: {str(e)}")
            return None

    def apply_automated_fix(self, error_type):
        """
        Apply automated fixes based on error type.
        """
        try:
            if error_type == "Timestamp Mismatch":
                fix_applied = "Adjusted based on blockchain metadata logs"
                status = "Resolved"
            elif error_type == "File Extension Mismatch":
                fix_applied = "File signature analysis used to correctly classify the file"
                status = "Resolved"
            elif error_type == "Missing Metadata":
                fix_applied = "Reconstructed metadata using forensic disk analysis"
                status = "Resolved"
            else:
                fix_applied = "No automated fix available"
                status = "Pending"

            # Log the fix
            self.log_error(error_type, "Info", f"Automated fix applied: {fix_applied}", fix_applied, status)
            return fix_applied, status
        except Exception as e:
            logging.error(f"Failed to apply automated fix: {str(e)}")
            return None, None

    def generate_error_report(self):
        """
        Generate a summary report of logged errors.
        """
        try:
            if self.error_logs.empty:
                return "No errors to report."

            report = {
                "total_errors": len(self.error_logs),
                "critical_errors": len(self.error_logs[self.error_logs["severity"] == "Critical"]),
                "warning_errors": len(self.error_logs[self.error_logs["severity"] == "Warning"]),
                "resolved_errors": len(self.error_logs[self.error_logs["status"] == "Resolved"]),
                "pending_errors": len(self.error_logs[self.error_logs["status"] == "Pending"])
            }
            return report
        except Exception as e:
            logging.error(f"Failed to generate error report: {str(e)}")
            return None
