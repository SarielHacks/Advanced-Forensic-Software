import logging
import traceback
import json
import os
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Callable, Optional, Tuple
from enum import Enum
import threading
import sqlite3
from collections import defaultdict, Counter

class ErrorSeverity(Enum):
    """Error severity classification"""
    CRITICAL = 5    # System failure, requires immediate attention
    HIGH = 4        # Functionality broken, needs urgent attention
    MEDIUM = 3      # Degraded operation, needs attention soon
    LOW = 2         # Minor issue, can be addressed later
    INFO = 1        # Informational only

class ErrorCategory(Enum):
    """Error category classification"""
    SYSTEM = "system"               # Operating system/hardware errors
    NETWORK = "network"             # Network connectivity issues
    DATABASE = "database"           # Database errors
    FILESYSTEM = "filesystem"       # File system access issues
    MEMORY = "memory"               # Memory allocation/access errors
    PROCESS = "process"             # Process execution errors
    VALIDATION = "validation"       # Input validation errors
    AUTHENTICATION = "authentication" # Authentication/authorization errors
    INTEGRATION = "integration"     # Component integration errors
    UNDEFINED = "undefined"         # Uncategorized errors

class ErrorManager:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        """Singleton pattern implementation"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ErrorManager, cls).__new__(cls)
            return cls._instance
    
    def __init__(self, log_dir: str = 'error_logs', db_path: str = 'error_analytics.db'):
        """
        Initialize the Error Management System
        
        :param log_dir: Directory for error log files
        :param db_path: Path to SQLite database for error analytics
        """
        # Prevent re-initialization of singleton
        if hasattr(self, 'initialized'):
            return
        self.initialized = True
        
        # Create log directory
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        # Setup logging
        self.logger = self._setup_logger()
        
        # Database setup
        self.db_path = db_path
        self._init_database()
        
        # Recovery handlers by error category
        self.recovery_handlers = {}
        
        # Default recovery strategies
        self._register_default_recovery_handlers()
        
        # Error counter for trending
        self.error_counter = defaultdict(int)
        
        # Error context for the current thread
        self.error_context = threading.local()
        self.error_context.component = "unknown"
        
        self.logger.info("Error Management System initialized")

    def _setup_logger(self) -> logging.Logger:
        """Set up the error logging system"""
        logger = logging.getLogger('error_manager')
        logger.setLevel(logging.DEBUG)
        
        # File handler for all errors
        file_handler = logging.FileHandler(os.path.join(self.log_dir, 'error.log'))
        file_handler.setLevel(logging.INFO)
        
        # Console handler for critical errors
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        
        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(component)s] - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger

    def _init_database(self):
        """Initialize the SQLite database for error analytics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS errors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    component TEXT,
                    error_type TEXT,
                    category TEXT,
                    severity TEXT,
                    message TEXT,
                    stack_trace TEXT,
                    context TEXT,
                    recovery_attempts INTEGER,
                    recovery_success INTEGER
                )
            ''')
            conn.commit()

    def set_context(self, component: str):
        """
        Set the component context for error handling
        
        :param component: Current component name
        """
        self.error_context.component = component
        
    def _get_context(self) -> Dict[str, Any]:
        """Get the current execution context for the error"""
        return {
            'component': getattr(self.error_context, 'component', 'unknown'),
            'thread_id': threading.get_ident(),
            'timestamp': datetime.now().isoformat()
        }

    def _classify_error(self, error: Exception) -> Tuple[ErrorSeverity, ErrorCategory]:
        """
        Classify the error by severity and category
        
        :param error: The exception to classify
        :return: Tuple of (ErrorSeverity, ErrorCategory)
        """
        # Default classification
        severity = ErrorSeverity.MEDIUM
        category = ErrorCategory.UNDEFINED
        
        # Classify based on exception type
        error_class = error.__class__.__name__
        
        # Severity classification
        if error_class in ('SystemExit', 'KeyboardInterrupt'):
            severity = ErrorSeverity.CRITICAL
        elif error_class in ('MemoryError', 'SystemError', 'IOError'):
            severity = ErrorSeverity.HIGH
        elif error_class in ('ValueError', 'TypeError', 'KeyError'):
            severity = ErrorSeverity.MEDIUM
        elif error_class in ('Warning', 'DeprecationWarning'):
            severity = ErrorSeverity.LOW
        
        # Category classification
        if any(x in error_class for x in ('OS', 'System')):
            category = ErrorCategory.SYSTEM
        elif any(x in error_class for x in ('Connection', 'Socket', 'Http')):
            category = ErrorCategory.NETWORK
        elif any(x in error_class for x in ('SQL', 'DB', 'Database')):
            category = ErrorCategory.DATABASE
        elif any(x in error_class for x in ('IO', 'File', 'Directory', 'Path')):
            category = ErrorCategory.FILESYSTEM
        elif any(x in error_class for x in ('Memory', 'Buffer', 'Overflow')):
            category = ErrorCategory.MEMORY
        elif 'Process' in error_class:
            category = ErrorCategory.PROCESS
        elif any(x in error_class for x in ('Value', 'Type', 'Argument', 'Attribute')):
            category = ErrorCategory.VALIDATION
        elif any(x in error_class for x in ('Auth', 'Permission', 'Access')):
            category = ErrorCategory.AUTHENTICATION
        elif any(x in error_class for x in ('Import', 'Module', 'Package', 'Component')):
            category = ErrorCategory.INTEGRATION
            
        return severity, category

    def _register_default_recovery_handlers(self):
        """Register default recovery handlers for each error category"""
        self.register_recovery_handler(ErrorCategory.NETWORK, self._recover_network)
        self.register_recovery_handler(ErrorCategory.DATABASE, self._recover_database)
        self.register_recovery_handler(ErrorCategory.FILESYSTEM, self._recover_filesystem)
        # Add more default handlers as needed

    def register_recovery_handler(self, category: ErrorCategory, handler: Callable):
        """
        Register a recovery handler for a specific error category
        
        :param category: Error category to handle
        :param handler: Recovery function to call
        """
        self.recovery_handlers[category] = handler
        self.logger.info(f"Registered recovery handler for {category.value}")

    def handle_error(self, error: Exception, context: Dict[str, Any] = None) -> bool:
        """
        Global error handler - logs, categorizes and attempts recovery
        
        :param error: The exception to handle
        :param context: Additional context information
        :return: True if recovery was successful, False otherwise
        """
        # Get error context and stack trace
        ctx = self._get_context()
        if context:
            ctx.update(context)
        
        stack_trace = traceback.format_exc()
        
        # Classify error
        severity, category = self._classify_error(error)
        
        # Create detailed error record
        error_data = {
            'timestamp': ctx['timestamp'],
            'component': ctx['component'],
            'error_type': error.__class__.__name__,
            'category': category.value,
            'severity': severity.name,
            'message': str(error),
            'stack_trace': stack_trace,
            'context': json.dumps(ctx),
            'recovery_attempts': 0,
            'recovery_success': 0
        }
        
        # Log the error
        self._log_error(error_data, severity)
        
        # Store in database for analytics
        self._store_error(error_data)
        
        # Update error counter for trending
        error_key = f"{category.value}:{error.__class__.__name__}"
        self.error_counter[error_key] += 1
        
        # Attempt recovery if handler exists
        recovery_success = False
        if category in self.recovery_handlers:
            try:
                recovery_success = self.recovery_handlers[category](error, ctx)
                error_data['recovery_attempts'] = 1
                error_data['recovery_success'] = 1 if recovery_success else 0
                self._update_error_recovery(error_data)
            except Exception as recovery_error:
                self.logger.error(f"Recovery failed: {recovery_error}")
        
        return recovery_success

    def _log_error(self, error_data: Dict[str, Any], severity: ErrorSeverity):
        """
        Log the error with appropriate severity
        
        :param error_data: Error information
        :param severity: Error severity level
        """
        # Map ErrorSeverity to logging levels
        log_levels = {
            ErrorSeverity.CRITICAL: logging.CRITICAL,
            ErrorSeverity.HIGH: logging.ERROR,
            ErrorSeverity.MEDIUM: logging.WARNING,
            ErrorSeverity.LOW: logging.INFO,
            ErrorSeverity.INFO: logging.DEBUG
        }
        
        # Create log message with extra context for formatter
        log_level = log_levels.get(severity, logging.ERROR)
        extra = {'component': error_data['component']}
        
        self.logger.log(
            log_level, 
            f"{error_data['error_type']}: {error_data['message']} [{error_data['category']}]", 
            extra=extra
        )

    def _store_error(self, error_data: Dict[str, Any]):
        """
        Store error in database for analytics
        
        :param error_data: Error data to store
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO errors (
                    timestamp, component, error_type, category, severity,
                    message, stack_trace, context, recovery_attempts, recovery_success
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                error_data['timestamp'],
                error_data['component'],
                error_data['error_type'],
                error_data['category'],
                error_data['severity'],
                error_data['message'],
                error_data['stack_trace'],
                error_data['context'],
                error_data['recovery_attempts'],
                error_data['recovery_success']
            ))
            conn.commit()

    def _update_error_recovery(self, error_data: Dict[str, Any]):
        """
        Update error recovery status in database
        
        :param error_data: Error data with updated recovery information
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE errors 
                SET recovery_attempts = ?, recovery_success = ?
                WHERE timestamp = ? AND component = ? AND error_type = ?
            ''', (
                error_data['recovery_attempts'],
                error_data['recovery_success'],
                error_data['timestamp'],
                error_data['component'],
                error_data['error_type']
            ))
            conn.commit()

    # Default recovery handlers
    def _recover_network(self, error: Exception, context: Dict[str, Any]) -> bool:
        """Default network error recovery strategy"""
        self.logger.info("Attempting network recovery...")
        # Implement retry logic or connection reset
        time.sleep(1)  # Wait before retry
        return True  # Assume success for this example

    def _recover_database(self, error: Exception, context: Dict[str, Any]) -> bool:
        """Default database error recovery strategy"""
        self.logger.info("Attempting database recovery...")
        # Implement connection pool reset or transaction rollback
        return False  # Assume failure for this example

    def _recover_filesystem(self, error: Exception, context: Dict[str, Any]) -> bool:
        """Default filesystem error recovery strategy"""
        self.logger.info("Attempting filesystem recovery...")
        # Implement alternative file access or cleanup
        return True  # Assume success for this example

    def analyze_trends(self, time_period: timedelta = timedelta(days=7)) -> Dict[str, Any]:
        """
        Analyze error trends over the specified time period
        
        :param time_period: Time period for analysis
        :return: Dictionary with trend analysis
        """
        start_time = (datetime.now() - time_period).isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Get error frequency by category
            cursor.execute('''
                SELECT category, COUNT(*) as count 
                FROM errors 
                WHERE timestamp > ? 
                GROUP BY category 
                ORDER BY count DESC
            ''', (start_time,))
            category_counts = dict(cursor.fetchall())
            
            # Get most common error types
            cursor.execute('''
                SELECT error_type, COUNT(*) as count 
                FROM errors 
                WHERE timestamp > ? 
                GROUP BY error_type 
                ORDER BY count DESC 
                LIMIT 5
            ''', (start_time,))
            common_errors = dict(cursor.fetchall())
            
            # Get recovery statistics
            cursor.execute('''
                SELECT 
                    SUM(recovery_attempts) as total_attempts,
                    SUM(recovery_success) as successful_recoveries,
                    COUNT(*) as total_errors
                FROM errors 
                WHERE timestamp > ?
            ''', (start_time,))
            recovery_stats = cursor.fetchone()
            
            # Get component reliability
            cursor.execute('''
                SELECT component, COUNT(*) as error_count 
                FROM errors 
                WHERE timestamp > ? 
                GROUP BY component 
                ORDER BY error_count DESC
            ''', (start_time,))
            component_errors = dict(cursor.fetchall())
            
        # Calculate recovery success rate
        recovery_rate = 0
        if recovery_stats[0] > 0:
            recovery_rate = (recovery_stats[1] / recovery_stats[0]) * 100
            
        return {
            'total_errors': recovery_stats[2],
            'error_by_category': category_counts,
            'most_common_errors': common_errors,
            'recovery_rate': recovery_rate,
            'component_error_counts': component_errors,
            'period': str(time_period)
        }

    def generate_error_report(self, 
                              time_period: timedelta = timedelta(days=1),
                              min_severity: ErrorSeverity = ErrorSeverity.MEDIUM) -> List[Dict[str, Any]]:
        """
        Generate a comprehensive error report
        
        :param time_period: Time period for the report
        :param min_severity: Minimum severity level to include
        :return: List of error records
        """
        start_time = (datetime.now() - time_period).isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM errors 
                WHERE timestamp > ? 
                  AND severity IN (?, ?, ?, ?, ?)
                ORDER BY timestamp DESC
            ''', (
                start_time,
                ErrorSeverity.CRITICAL.name,
                ErrorSeverity.HIGH.name,
                ErrorSeverity.MEDIUM.name,
                ErrorSeverity.LOW.name,
                ErrorSeverity.INFO.name
            ))
            
            columns = [column[0] for column in cursor.description]
            errors = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
        # Filter by minimum severity
        severity_order = {sev.name: sev.value for sev in ErrorSeverity}
        filtered_errors = [
            error for error in errors
            if severity_order.get(error['severity'], 0) >= min_severity.value
        ]
            
        return filtered_errors

def example_usage():
    """Example usage of the Error Management System"""
    # Initialize the error manager
    error_manager = ErrorManager()
    
    # Set component context
    error_manager.set_context("filesystem_analyzer")
    
    try:
        # Simulate an error
        result = 1 / 0
    except Exception as e:
        # Handle the error
        recovery_success = error_manager.handle_error(e, {'operation': 'division'})
        print(f"Recovery {'successful' if recovery_success else 'failed'}")
    
    # Generate trend analysis
    trends = error_manager.analyze_trends(timedelta(hours=1))
    print(f"Error Trends: {json.dumps(trends, indent=2)}")
    
    # Generate error report
    report = error_manager.generate_error_report(timedelta(hours=1))
    print(f"Error Report: {len(report)} errors found")

if __name__ == "__main__":
    example_usage()
