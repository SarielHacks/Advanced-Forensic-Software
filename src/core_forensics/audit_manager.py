import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List
import hashlib
import sqlite3

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
            
            prolonged_actions = cursor.fetchall()
            
            for action in prolonged_actions:
                self.logger.warning(f"Compliance Alert: Prolonged Action Detected - {action}")
            
            # Check for critical actions
            for action in critical_actions:
                cursor.execute('''
                    SELECT * FROM audit_trail 
                    WHERE action = ? 
                    ORDER BY timestamp DESC 
                    LIMIT 5
                ''', (action,))
                
                critical_action_logs = cursor.fetchall()
                
                if critical_action_logs:
                    self.logger.warning(f"Compliance Monitoring: Critical Action {action} Detected")

    def generate_audit_report(self, 
                               start_time: datetime = None, 
                               end_time: datetime = None) -> List[Dict[str, Any]]:
        """
        Generate a comprehensive audit report
        
        :param start_time: Start time for the report
        :param end_time: End time for the report
        :return: List of audit log entries
        """
        start_time = start_time or datetime.now() - timedelta(days=30)
        end_time = end_time or datetime.now()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM audit_trail 
                WHERE timestamp BETWEEN ? AND ?
                ORDER BY timestamp
            ''', (start_time.isoformat(), end_time.isoformat()))
            
            columns = [column[0] for column in cursor.description]
            audit_report = [
                dict(zip(columns, row)) for row in cursor.fetchall()
            ]
        
        return audit_report

def main():
    # Initialize Audit Manager
    audit_manager = AuditManager()
    
    # Log sample activities
    audit_manager.log_activity(
        user='forensics_analyst',
        action='evidence_collection',
        details={
            'case_id': 'CASE_2024_001',
            'evidence_type': 'digital_forensics',
            'source': 'hard_drive'
        }
    )
    
    # Monitor compliance
    audit_manager.monitor_compliance()
    
    # Generate audit report
    report = audit_manager.generate_audit_report()
    print("Audit Report:", json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
