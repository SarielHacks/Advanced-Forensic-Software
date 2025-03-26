import os
import pandas as pd
import numpy as np
from AI_ML.ml_utils import MLUtils
from CORE_FORENSICS.filesystem_analyzer import FilesystemAnalyzer
from CORE_FORENSICS.audit_manager import AuditManager
from AI_ML.ai_error_management import AIErrorManager
from transformers import BertTokenizer, TFBertForSequenceClassification
import tensorflow as tf

class AIAnalyzer:
    def __init__(self, error_manager: AIErrorManager, config: dict):
        """
        Initialize the AI Analyzer with required components.
        
        Args:
            error_manager (AIErrorManager): Error management instance
            config (dict): Configuration dictionary from main_config.yaml
        """
        self.error_manager = error_manager
        self.config = config
        
        # Initialize components with config paths
        try:
            self.ml_utils = MLUtils(error_manager)
            self.fs_analyzer = FilesystemAnalyzer(config["core_forensics"]["root_path"])
            self.audit_manager = AuditManager(config["core_forensics"]["audit_logs_directory"])
            
            # Initialize NLP components
            self.tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
            self.nlp_model = TFBertForSequenceClassification.from_pretrained(
                'bert-base-uncased', 
                num_labels=2
            )
            
            # Load or initialize other models as needed
            self._initialize_models()
            
        except Exception as e:
            self.error_manager.log_error(
                "AI Analyzer Initialization Error",
                "Critical",
                f"Failed to initialize AI Analyzer: {str(e)}"
            )
            raise

    def _initialize_models(self):
        """Initialize or load machine learning models."""
        # Placeholder for model initialization logic
        pass

    def detect_timestamp_anomalies(self, timestamps: list) -> np.ndarray:
        """Detect anomalies in timestamps using Isolation Forest."""
        try:
            if "IsolationForest" not in self.ml_utils.models:
                X = np.array(timestamps).reshape(-1, 1)
                self.ml_utils.train_model(
                    "IsolationForest", 
                    X, 
                    np.zeros(len(X)), 
                    n_estimators=100
                )
            
            anomalies = self.ml_utils.models["IsolationForest"].predict(
                np.array(timestamps).reshape(-1, 1))
            return anomalies == -1
        except Exception as e:
            self.error_manager.log_error(
                "Timestamp Anomaly Detection Error",
                "Critical",
                f"Error detecting timestamp anomalies: {str(e)}"
            )
            return None

    def detect_file_content_mismatch(self, file_path: str) -> bool:
        """Detect mismatches between file extensions and content."""
        try:
            file_type = self.fs_analyzer.detect_file_type(file_path)
            extension = os.path.splitext(file_path)[1].lower()
            return file_type != extension
        except Exception as e:
            self.error_manager.log_error(
                "File Content Mismatch Error",
                "Warning",
                f"Error detecting file content mismatch for {file_path}: {str(e)}"
            )
            return None

    def detect_suspicious_text(self, text: str) -> bool:
        """Detect suspicious or unlawful text using BERT-based NLP."""
        try:
            inputs = self.tokenizer(
                text, 
                return_tensors="tf", 
                truncation=True, 
                padding=True, 
                max_length=512
            )
            outputs = self.nlp_model(inputs)
            predictions = tf.argmax(outputs.logits, axis=-1)
            return predictions.numpy()[0] == 1
        except Exception as e:
            self.error_manager.log_error(
                "Suspicious Text Detection Error",
                "Critical",
                f"Error detecting suspicious text: {str(e)}"
            )
            return None

    def analyze_forensic_data(self, data: pd.DataFrame) -> pd.DataFrame:
        """Analyze forensic data for anomalies and suspicious patterns."""
        results = []
        
        for _, row in data.iterrows():
            try:
                timestamp_anomaly = self.detect_timestamp_anomalies([row["timestamp"]])
                file_mismatch = self.detect_file_content_mismatch(row["file_path"])
                suspicious_text = self.detect_suspicious_text(row["text_content"])

                results.append({
                    "file_path": row["file_path"],
                    "timestamp_anomaly": timestamp_anomaly[0] if timestamp_anomaly is not None else False,
                    "file_mismatch": file_mismatch if file_mismatch is not None else False,
                    "suspicious_text": suspicious_text if suspicious_text is not None else False,
                    "anomaly": row["anomaly"]
                })
            except Exception as e:
                self.error_manager.log_error(
                    "Forensic Data Analysis Error",
                    "Critical",
                    f"Error analyzing forensic data for file {row['file_path']}: {str(e)}"
                )

        return pd.DataFrame(results)

    def integrate_with_audit_manager(self, anomalies: pd.DataFrame):
        """Integrate detected anomalies with the audit manager."""
        for _, anomaly in anomalies.iterrows():
            try:
                if anomaly["timestamp_anomaly"]:
                    self.audit_manager.log_timestamp_anomaly(anomaly["file_path"])
                if anomaly["file_mismatch"]:
                    self.audit_manager.log_file_mismatch(anomaly["file_path"])
                if anomaly["suspicious_text"]:
                    self.audit_manager.log_suspicious_text(anomaly["file_path"])
            except Exception as e:
                self.error_manager.log_error(
                    "Audit Manager Integration Error",
                    "Warning",
                    f"Error integrating anomaly for file {anomaly['file_path']}: {str(e)}"
                )

    def generate_report(self, results: pd.DataFrame) -> dict:
        """Generate a forensic report based on analysis results."""
        try:
            return {
                "total_files_analyzed": len(results),
                "timestamp_anomalies": results["timestamp_anomaly"].sum(),
                "file_mismatches": results["file_mismatch"].sum(),
                "suspicious_text_detected": results["suspicious_text"].sum(),
                "anomalies_detected": results["anomaly"].sum()
            }
        except Exception as e:
            self.error_manager.log_error(
                "Report Generation Error",
                "Critical",
                f"Error generating forensic report: {str(e)}"
            )
            return None
