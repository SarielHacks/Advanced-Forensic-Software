import sqlite3
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

class ForensicDatabaseManager:
    def __init__(self, database_path: str = 'forensic_case_database.sqlite'):
        """
        Initialize the forensic database manager
        
        :param database_path: Path to the SQLite database file
        """
        self.db_path = database_path
        self.conn = None
        self.cursor = None
        
        # Configure SQLite to use UTC timestamps
        sqlite3.register_adapter(datetime, self._adapt_datetime)
        sqlite3.register_converter('DATETIME', self._convert_datetime)
        
        self._initialize_database()

    @staticmethod
    def _adapt_datetime(dt: datetime) -> str:
        """
        Adapt datetime to ISO format string for SQLite storage
        
        :param dt: Datetime object
        :return: ISO formatted string
        """
        return dt.astimezone(timezone.utc).isoformat()

    @staticmethod
    def _convert_datetime(dt_bytes: bytes) -> datetime:
        """
        Convert SQLite stored datetime string back to datetime object
        
        :param dt_bytes: Bytes representation of datetime
        :return: Datetime object
        """
        dt_str = dt_bytes.decode('utf-8')
        return datetime.fromisoformat(dt_str).replace(tzinfo=timezone.utc)

    def _initialize_database(self):
        """Create necessary tables if they don't exist"""
        try:
            # Use detect_types to enable datetime conversion
            self.conn = sqlite3.connect(
                self.db_path, 
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
            )
            self.cursor = self.conn.cursor()

            # Case management table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    case_name TEXT,
                    investigator TEXT,
                    status TEXT,
                    created_at DATETIME,
                    description TEXT
                )
            ''')

            # Evidence cataloguing table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    case_id TEXT,
                    evidence_type TEXT,
                    source TEXT,
                    collection_date DATETIME,
                    hash TEXT,
                    metadata JSON,
                    FOREIGN KEY(case_id) REFERENCES cases(case_id)
                )
            ''')

            # Evidence analysis results table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS analysis_results (
                    result_id TEXT PRIMARY KEY,
                    evidence_id TEXT,
                    analysis_type TEXT,
                    findings TEXT,
                    analyzed_at DATETIME,
                    FOREIGN KEY(evidence_id) REFERENCES evidence(evidence_id)
                )
            ''')

            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")

    def create_case(self, case_name: str, investigator: str, description: str = '') -> str:
        """
        Create a new forensic case
        
        :param case_name: Name of the case
        :param investigator: Lead investigator
        :param description: Optional case description
        :return: Generated case ID
        """
        case_id = str(uuid.uuid4())
        try:
            self.cursor.execute('''
                INSERT INTO cases 
                (case_id, case_name, investigator, status, created_at, description)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                case_id, 
                case_name, 
                investigator, 
                'ACTIVE', 
                datetime.now(timezone.utc),  # Use UTC timezone 
                description
            ))
            self.conn.commit()
            return case_id
        except sqlite3.Error as e:
            print(f"Error creating case: {e}")
            return ''

    def add_evidence(self, case_id: str, evidence_type: str, source: str, metadata: Dict = None) -> str:
        """
        Add evidence to a case
        
        :param case_id: ID of the case
        :param evidence_type: Type of evidence
        :param source: Source/path of the evidence
        :param metadata: Additional metadata about the evidence
        :return: Generated evidence ID
        """
        evidence_id = str(uuid.uuid4())
        file_hash = self._calculate_file_hash(source) if Path(source).is_file() else ''

        try:
            self.cursor.execute('''
                INSERT INTO evidence 
                (evidence_id, case_id, evidence_type, source, collection_date, hash, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                evidence_id, 
                case_id, 
                evidence_type, 
                source, 
                datetime.now(timezone.utc),  # Use UTC timezone
                file_hash,
                json.dumps(metadata or {})
            ))
            self.conn.commit()
            return evidence_id
        except sqlite3.Error as e:
            print(f"Error adding evidence: {e}")
            return ''

    def _calculate_file_hash(self, file_path: str) -> str:
        """
        Calculate SHA-256 hash of a file
        
        :param file_path: Path to the file
        :return: Hash of the file
        """
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ''

    def record_analysis_result(self, evidence_id: str, analysis_type: str, findings: str) -> str:
        """
        Record analysis results for a piece of evidence
        
        :param evidence_id: ID of the evidence
        :param analysis_type: Type of analysis performed
        :param findings: Analysis findings
        :return: Generated result ID
        """
        result_id = str(uuid.uuid4())
        try:
            self.cursor.execute('''
                INSERT INTO analysis_results 
                (result_id, evidence_id, analysis_type, findings, analyzed_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                result_id, 
                evidence_id, 
                analysis_type, 
                findings, 
                datetime.now(timezone.utc)  # Use UTC timezone
            ))
            self.conn.commit()
            return result_id
        except sqlite3.Error as e:
            print(f"Error recording analysis result: {e}")
            return ''

    def query_cases(self, **kwargs) -> List[Dict]:
        """
        Query cases with flexible filtering
        
        :param kwargs: Filtering parameters
        :return: List of matching cases
        """
        query = "SELECT * FROM cases WHERE 1=1"
        params = []
        
        for key, value in kwargs.items():
            query += f" AND {key} = ?"
            params.append(value)
        
        try:
            self.cursor.execute(query, params)
            columns = [col[0] for col in self.cursor.description]
            return [dict(zip(columns, row)) for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"Query error: {e}")
            return []

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

# Example use cases
def main():
    # Initialize database
    db = ForensicDatabaseManager()

    # Create a new case
    case_id = db.create_case(
        case_name="Digital Forensics Investigation",
        investigator="Hardik Jas",
        description="Comprehensive digital evidence analysis"
    )

    # Add evidence to the case
    evidence_id = db.add_evidence(
        case_id=case_id,
        evidence_type="Hard Drive",
        source="/path/to/evidence/drive",
        metadata={
            "manufacturer": "Western Digital",
            "capacity": "1TB",
            "acquisition_method": "Disk Image"
        }
    )

    # Record analysis results
    db.record_analysis_result(
        evidence_id=evidence_id,
        analysis_type="File System Analysis",
        findings="Multiple deleted files recovered"
    )

    # Query cases
    active_cases = db.query_cases(status="ACTIVE")
    print(active_cases)

    # Close database connection
    db.close()

if __name__ == "__main__":
    main()
