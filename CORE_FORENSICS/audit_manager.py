import os
import json
import logging
import statistics
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import hashlib
import sqlite3
import time

class AuditManager:
    def __init__(self, audit_log_dir: str = 'audit_logs'):
        """
        Initialize Audit Manager
        
        :param audit_log_dir: Directory to store audit logs
        """
        # Create audit log directory if not exists
        self.audit_log_dir = audit_log_dir
        os.makedirs(audit_log_dir, exist_ok=True)
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Setup SQLite database for audit trail
        self.db_path = os.path.join(audit_log_dir, 'audit_trail.db')
        self._initialize_database()

    def _initialize_database(self):
        """
        Initialize SQLite database for audit trail
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_trail (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    user TEXT,
                    action TEXT,
                    details TEXT,
                    hash TEXT
                )
            ''')
            
            # Create table for file metadata timestamps
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_metadata (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filepath TEXT UNIQUE,
                    created_time DATETIME,
                    modified_time DATETIME,
                    accessed_time DATETIME,
                    validated_time DATETIME,
                    status TEXT,
                    anomaly_score REAL
                )
            ''')
            
            # Create table for timestamp anomalies
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS timestamp_anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detection_time DATETIME,
                    filepath TEXT,
                    anomaly_type TEXT,
                    details TEXT,
                    severity TEXT
                )
            ''')
            conn.commit()

    def log_activity(self, user: str, action: str, details: Dict[str, Any]):
        """
        Log system activity with comprehensive details
        
        :param user: User performing the action
        :param action: Type of action performed
        :param details: Additional details about the action
        """
        timestamp = datetime.now()
        
        # Prepare log entry
        log_entry = {
            'timestamp': timestamp.isoformat(),
            'user': user,
            'action': action,
            'details': json.dumps(details)
        }
        
        # Generate secure hash of the log entry
        log_hash = self._generate_hash(log_entry)
        log_entry['hash'] = log_hash
        
        # Log to file
        log_filename = f"{timestamp.strftime('%Y%m%d')}_audit.log"
        log_path = os.path.join(self.audit_log_dir, log_filename)
        
        with open(log_path, 'a') as log_file:
            log_file.write(json.dumps(log_entry) + '\n')
        
        # Store in database
        self._store_audit_trail(log_entry)
        
        # Log to console
        self.logger.info(f"Audit Log: {action} by {user}")

    def _generate_hash(self, log_entry: Dict[str, Any]) -> str:
        """
        Generate a secure hash for the log entry
        
        :param log_entry: Log entry dictionary
        :return: SHA-256 hash of the log entry
        """
        entry_string = json.dumps(log_entry, sort_keys=True)
        return hashlib.sha256(entry_string.encode()).hexdigest()

    def _store_audit_trail(self, log_entry: Dict[str, Any]):
        """
        Store audit trail in SQLite database
        
        :param log_entry: Log entry to store
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO audit_trail 
                (timestamp, user, action, details, hash) 
                VALUES (?, ?, ?, ?, ?)
            ''', (
                log_entry['timestamp'],
                log_entry['user'],
                log_entry['action'],
                log_entry['details'],
                log_entry['hash']
            ))
            conn.commit()

    def validate_file_timestamps(self, filepath: str) -> Dict[str, Any]:
        """
        Validate file metadata timestamps and detect anomalies
        
        :param filepath: Path to the file
        :return: Dictionary containing validation results
        """
        if not os.path.exists(filepath):
            self.logger.error(f"File not found: {filepath}")
            return {"status": "error", "message": "File not found"}
        
        # Get file metadata timestamps
        created_time = datetime.fromtimestamp(os.path.getctime(filepath))
        modified_time = datetime.fromtimestamp(os.path.getmtime(filepath))
        accessed_time = datetime.fromtimestamp(os.path.getatime(filepath))
        validated_time = datetime.now()
        
        # Check for obvious inconsistencies
        anomalies = []
        anomaly_score = 0.0
        
        # Check if modification time is earlier than creation time
        if modified_time < created_time:
            anomalies.append({
                "type": "timestamp_inconsistency",
                "details": f"Modified time ({modified_time}) is earlier than creation time ({created_time})",
                "severity": "high"
            })
            anomaly_score += 5.0
        
        # Check if access time is earlier than creation time
        if accessed_time < created_time:
            anomalies.append({
                "type": "timestamp_inconsistency",
                "details": f"Access time ({accessed_time}) is earlier than creation time ({created_time})",
                "severity": "medium"
            })
            anomaly_score += 3.0
        
        # Check if any timestamps are in the future
        current_time = datetime.now()
        for timestamp_type, timestamp in [
            ("created", created_time),
            ("modified", modified_time),
            ("accessed", accessed_time)
        ]:
            if timestamp > current_time + timedelta(minutes=5):  # Allow small time differences
                anomalies.append({
                    "type": "future_timestamp",
                    "details": f"{timestamp_type.capitalize()} time ({timestamp}) is in the future",
                    "severity": "high"
                })
                anomaly_score += 5.0
        
        # Store file metadata
        status = "anomalous" if anomalies else "valid"
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO file_metadata 
                (filepath, created_time, modified_time, accessed_time, validated_time, status, anomaly_score) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                filepath,
                created_time.isoformat(),
                modified_time.isoformat(),
                accessed_time.isoformat(),
                validated_time.isoformat(),
                status,
                anomaly_score
            ))
            
            # Store anomalies if any
            for anomaly in anomalies:
                cursor.execute('''
                    INSERT INTO timestamp_anomalies 
                    (detection_time, filepath, anomaly_type, details, severity) 
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    validated_time.isoformat(),
                    filepath,
                    anomaly["type"],
                    anomaly["details"],
                    anomaly["severity"]
                ))
            
            conn.commit()
        
        result = {
            "filepath": filepath,
            "created_time": created_time.isoformat(),
            "modified_time": modified_time.isoformat(),
            "accessed_time": accessed_time.isoformat(),
            "validated_time": validated_time.isoformat(),
            "status": status,
            "anomaly_score": anomaly_score,
            "anomalies": anomalies
        }
        
        # Log validation results
        self.log_activity("system", "file_timestamp_validation", {
            "filepath": filepath,
            "status": status,
            "anomaly_score": anomaly_score,
            "anomalies_count": len(anomalies)
        })
        
        return result

    def detect_timestamp_anomalies(self, directory: str = None, threshold: float = 3.0) -> List[Dict[str, Any]]:
        """
        Detect timestamp anomalies across files using statistical methods
        
        :param directory: Directory to scan (None to use existing database entries)
        :param threshold: Z-score threshold for anomaly detection
        :return: List of detected anomalies
        """
        # If directory is provided, validate all files in it first
        if directory and os.path.isdir(directory):
            for root, _, files in os.walk(directory):
                for file in files:
                    filepath = os.path.join(root, file)
                    self.validate_file_timestamps(filepath)
        
        # Perform anomaly detection using z-score method
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Get all file metadata entries
            cursor.execute('''
                SELECT filepath, created_time, modified_time, accessed_time, validated_time
                FROM file_metadata
            ''')
            
            file_data = cursor.fetchall()
            
            # Calculate time differences
            create_modify_diffs = []
            modify_access_diffs = []
            
            for filepath, created_time, modified_time, accessed_time, _ in file_data:
                created_dt = datetime.fromisoformat(created_time)
                modified_dt = datetime.fromisoformat(modified_time)
                accessed_dt = datetime.fromisoformat(accessed_time)
                
                create_modify_diff = abs((modified_dt - created_dt).total_seconds())
                modify_access_diff = abs((accessed_dt - modified_dt).total_seconds())
                
                create_modify_diffs.append((filepath, create_modify_diff))
                modify_access_diffs.append((filepath, modify_access_diff))
            
            # Calculate statistics
            if len(create_modify_diffs) < 2:
                self.logger.warning("Not enough data for statistical analysis")
                return []
            
            cm_values = [diff for _, diff in create_modify_diffs]
            ma_values = [diff for _, diff in modify_access_diffs]
            
            cm_mean = statistics.mean(cm_values) if cm_values else 0
            cm_stdev = statistics.stdev(cm_values) if len(cm_values) > 1 else 0
            
            ma_mean = statistics.mean(ma_values) if ma_values else 0
            ma_stdev = statistics.stdev(ma_values) if len(ma_values) > 1 else 0
            
            # Detect anomalies using z-score
            anomalies = []
            
            for filepath, diff in create_modify_diffs:
                if cm_stdev > 0:
                    z_score = abs((diff - cm_mean) / cm_stdev)
                    if z_score > threshold:
                        anomalies.append({
                            "filepath": filepath,
                            "anomaly_type": "create_modify_time_anomaly",
                            "details": f"Unusual time difference between creation and modification (Z-score: {z_score:.2f})",
                            "severity": "medium" if z_score < 5 else "high",
                            "z_score": z_score
                        })
            
            for filepath, diff in modify_access_diffs:
                if ma_stdev > 0:
                    z_score = abs((diff - ma_mean) / ma_stdev)
                    if z_score > threshold:
                        anomalies.append({
                            "filepath": filepath,
                            "anomaly_type": "modify_access_time_anomaly",
                            "details": f"Unusual time difference between modification and access (Z-score: {z_score:.2f})",
                            "severity": "medium" if z_score < 5 else "high",
                            "z_score": z_score
                        })
            
            # Store detected anomalies
            detection_time = datetime.now().isoformat()
            
            for anomaly in anomalies:
                cursor.execute('''
                    INSERT INTO timestamp_anomalies 
                    (detection_time, filepath, anomaly_type, details, severity) 
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    detection_time,
                    anomaly["filepath"],
                    anomaly["anomaly_type"],
                    anomaly["details"],
                    anomaly["severity"]
                ))
            
            conn.commit()
            
            # Log anomaly detection results
            self.log_activity("system", "timestamp_anomaly_detection", {
                "total_files": len(file_data),
                "anomalies_detected": len(anomalies),
                "threshold": threshold
            })
            
            return anomalies

    def get_timestamp_anomalies(self, 
                                start_time: Optional[datetime] = None, 
                                end_time: Optional[datetime] = None,
                                severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieve timestamp anomalies from the database
        
        :param start_time: Start time for filtering anomalies
        :param end_time: End time for filtering anomalies
        :param severity: Filter by severity level (high, medium, low)
        :return: List of anomalies
        """
        start_time = start_time or datetime.now() - timedelta(days=30)
        end_time = end_time or datetime.now()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            query = '''
                SELECT * FROM timestamp_anomalies 
                WHERE detection_time BETWEEN ? AND ?
            '''
            params = [start_time.isoformat(), end_time.isoformat()]
            
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            
            cursor.execute(query, params)
            
            columns = [column[0] for column in cursor.description]
            anomalies = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            return anomalies

    def monitor_compliance(self, 
                            max_duration: timedelta = timedelta(hours=8),
                            critical_actions: List[str] = None):
        """
        Monitor system compliance and flag potential violations
        
        :param max_duration: Maximum allowed duration for continuous actions
        :param critical_actions: List of actions requiring immediate attention
        """
        critical_actions = critical_actions or [
            'data_modification', 
            'system_configuration_change', 
            'access_control_modification'
        ]
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Check for prolonged system actions
            cursor.execute('''
                SELECT user, action, 
                       MAX(timestamp) - MIN(timestamp) as action_duration
                FROM audit_trail
                GROUP BY user, action
                HAVING action_duration > ?
            ''', (max_duration.total_seconds(),))
            
            prolonged_actions = cursor.fetchall
