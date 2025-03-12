from typing import Dict, List, Optional, Tuple, Union, Any, Callable, TypeVar, Generic
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler, RobustScaler, PowerTransformer
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError
import joblib
import logging
from logging import handlers
import hashlib
import json
from datetime import datetime
from pathlib import Path
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
from dataclasses import dataclass, field
import torch
from torch.utils.data import Dataset, DataLoader
import tempfile
import shutil
import os
from contextlib import contextmanager
import pickle
from cryptography.fernet import Fernet
import secrets
import uuid
from abc import ABC, abstractmethod
from transformers import pipeline

# Type variables for generic type hints
T = TypeVar('T')
ModelType = TypeVar('ModelType', bound=BaseEstimator)
# Load NLP model
nlp_model = pipeline("text-classification", model="nlptown/bert-base-multilingual-uncased-sentiment")


@dataclass
class ModelVersion:
    major: int
    minor: int
    patch: int
    
    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"
    
    @classmethod
    def from_string(cls, version_str: str) -> 'ModelVersion':
        major, minor, patch = map(int, version_str.split('.'))
        return cls(major, minor, patch)

class SecurityError(Exception):
    """Custom exception for security-related errors."""
    pass

@dataclass
class ModelMetadata:
    """Enhanced model metadata for tracking and validation."""
    model_id: str
    creation_date: datetime
    last_updated: datetime
    training_data_hash: str
    performance_metrics: Dict[str, float]
    feature_columns: List[str]
    model_parameters: Dict[str, Any]
    version: str
    author: str = field(default="system")
    description: str = field(default="")
    tags: List[str] = field(default_factory=list)
    validation_history: List[Dict[str, Any]] = field(default_factory=list)
    security_hash: str = field(init=False)
    
    def __post_init__(self):
        """Generate security hash after initialization."""
        self.security_hash = self._generate_security_hash()
    
    def _generate_security_hash(self) -> str:
        """Generate a secure hash of critical metadata fields."""
        critical_fields = f"{self.model_id}{self.creation_date}{self.training_data_hash}"
        return hashlib.blake2b(critical_fields.encode(), digest_size=32).hexdigest()

class SecureDataHandler:
    """Handles secure data operations including encryption and validation."""
    
    def __init__(self, encryption_key: Optional[str] = None):
        self.encryption_key = encryption_key or Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt binary data."""
        return self.cipher_suite.encrypt(data)
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt binary data."""
        return self.cipher_suite.decrypt(encrypted_data)
    
    def secure_wipe(self, data: bytes) -> None:
        """Securely wipe data from memory."""
        data_view = memoryview(data).cast('B')
        for i in range(len(data_view)):
            data_view[i] = 0
    
    @contextmanager
    def secure_temporary_file(self) -> Path:
        """Create a secure temporary file with proper cleanup."""
        temp_dir = tempfile.mkdtemp(prefix='secure_ml_')
        temp_file = Path(temp_dir) / f"temp_{secrets.token_hex(16)}"
        try:
            yield temp_file
        finally:
            if temp_file.exists():
                temp_file.write_bytes(b'0' * 1024)  # Overwrite with zeros
                temp_file.unlink()
            shutil.rmtree(temp_dir)

class ForensicDataset(Dataset):
    """Enhanced dataset class with security features for forensic data."""
    
    def __init__(self, features: np.ndarray, labels: Optional[np.ndarray] = None,
                 transform: Optional[Callable] = None):
        self.features = torch.FloatTensor(features)
        self.labels = torch.LongTensor(labels) if labels is not None else None
        self.transform = transform
        self._validate_data()
        
    def _validate_data(self) -> None:
        """Validate dataset integrity."""
        if torch.isnan(self.features).any():
            raise ValueError("Features contain NaN values")
        if self.labels is not None and torch.isnan(self.labels).any():
            raise ValueError("Labels contain NaN values")
        
    def __len__(self) -> int:
        return len(self.features)
        
    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, Optional[torch.Tensor]]:
        features = self.features[idx]
        if self.transform:
            features = self.transform(features)
        
        if self.labels is not None:
            return features, self.labels[idx]
        return features, None

class BaseModelManager(Generic[ModelType], ABC):
    """Abstract base class for model management."""
    
    @abstractmethod
    def save_model(self, model: ModelType, metadata: ModelMetadata) -> str:
        pass
    
    @abstractmethod
    def load_model(self, model_id: str, version: Optional[str] = None) -> Tuple[ModelType, ModelMetadata]:
        pass

class ModelManager(BaseModelManager[ModelType]):
    """Enhanced model lifecycle management system with advanced security features."""
    
    def __init__(self, model_path: str = "./models", use_gpu: bool = True,
                 encryption_key: Optional[str] = None):
        self.model_path = Path(model_path)
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        self.log_dir = Path("./logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger = self._setup_logger()
        self.use_gpu = use_gpu and torch.cuda.is_available()
        self.device = torch.device("cuda" if self.use_gpu else "cpu")
        self._model_cache = {}
        self._cache_lock = threading.Lock()
        self.secure_handler = SecureDataHandler(encryption_key)
        
    def _setup_logger(self) -> logging.Logger:
        """Configure comprehensive logging system with rotation."""
        logger = logging.getLogger("ModelManager")
        logger.setLevel(logging.INFO)
        
        log_file = self.log_dir / f"model_manager_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = handlers.RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5
        )
        file_handler.setLevel(logging.INFO)
        
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def _generate_model_hash(self, model: ModelType) -> str:
        """Generate cryptographically secure hash for model versioning."""
        model_params = json.dumps(model.get_params(), sort_keys=True)
        return hashlib.blake2b(model_params.encode(), digest_size=32).hexdigest()
    
    def save_model(self, model: ModelType, metadata: ModelMetadata) -> str:
        """Save model with encryption and integrity verification."""
        model_hash = self._generate_model_hash(model)
        save_path = self.model_path / f"{metadata.model_id}_{model_hash}.enc"
        
        model_package = {
            'model': model,
            'metadata': metadata,
            'hash': model_hash,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            with self.secure_handler.secure_temporary_file() as temp_file:
                # Serialize and encrypt
                serialized_data = pickle.dumps(model_package)
                encrypted_data = self.secure_handler.encrypt_data(serialized_data)
                
                # Save encrypted data
                save_path.write_bytes(encrypted_data)
                
                self.logger.info(f"Model saved successfully: {save_path}")
                return str(save_path)
        except Exception as e:
            self.logger.error(f"Error saving model: {str(e)}")
            raise SecurityError(f"Failed to save model securely: {str(e)}")
    
    def load_model(self, model_id: str, version: Optional[str] = None) -> Tuple[ModelType, ModelMetadata]:
        """Load model with encryption and integrity verification."""
        try:
            cache_key = f"{model_id}_{version}" if version else model_id
            with self._cache_lock:
                if cache_key in self._model_cache:
                    self.logger.info(f"Loading model {model_id} from cache")
                    return self._model_cache[cache_key]
            
            model_files = list(self.model_path.glob(f"{model_id}*.enc"))
            if not model_files:
                raise FileNotFoundError(f"No model found with ID: {model_id}")
            
            model_file = sorted(model_files)[-1] if version is None else next(
                (f for f in model_files if version in f.name),
                None
            )
            
            if model_file is None:
                raise ValueError(f"Version {version} not found for model {model_id}")
            
            # Load and decrypt model
            encrypted_data = model_file.read_bytes()
            with self.secure_handler.secure_temporary_file() as temp_file:
                decrypted_data = self.secure_handler.decrypt_data(encrypted_data)
                model_package = pickle.loads(decrypted_data)
                
                self._validate_model_package(model_package)
                
                with self._cache_lock:
                    self._model_cache[cache_key] = (
                        model_package['model'],
                        model_package['metadata']
                    )
                
                return model_package['model'], model_package['metadata']
                
        except Exception as e:
            self.logger.error(f"Error loading model {model_id}: {str(e)}")
            raise SecurityError(f"Failed to load model securely: {str(e)}")

    def _validate_model_package(self, package: Dict[str, Any]) -> None:
        """Validate loaded model package structure and security."""
        required_keys = {'model', 'metadata', 'hash', 'timestamp'}
        if not all(key in package for key in required_keys):
            raise SecurityError("Invalid model package structure")
            
        if not isinstance(package['metadata'], ModelMetadata):
            raise SecurityError("Invalid metadata format")
            
        current_hash = self._generate_model_hash(package['model'])
        if current_hash != package['hash']:
            raise SecurityError("Model hash verification failed")
            
        # Validate timestamp
        timestamp = datetime.fromisoformat(package['timestamp'])
        if timestamp > datetime.now():
            raise SecurityError("Invalid model timestamp")

class FeatureExtractor:
    """Enhanced feature extraction system with parallel processing capabilities."""
    
    def __init__(self, n_jobs: int = -1, feature_config: Optional[Dict[str, Any]] = None):
        self.n_jobs = self._validate_n_jobs(n_jobs)
        self.scalers = {
            'standard': StandardScaler(),
            'robust': RobustScaler(),
            'power': PowerTransformer(method='yeo-johnson')
        }
        self.feature_columns: List[str] = []
        self._extraction_queue = queue.Queue()
        self.feature_config = feature_config or {}
        
    def detect_suspicious_text(self, text):
        """Analyze text for suspicious content using NLP."""
        if not text.strip():
            return "No text content detected."

        results = nlp_model(text[:512])  # Analyze the first 512 characters
        return json.dumps(results, indent=2)

    def extract_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """Extract features including suspicious text detection."""
        features = pd.DataFrame(index=data.index)

        # If there is a 'content' column in the dataset, analyze it
        if 'content' in data.columns:
            features["suspicious_text_analysis"] = data['content'].apply(self.detect_suspicious_text)

        return featuresi 
    
    def _validate_n_jobs(self, n_jobs: int) -> int:
        """Validate and convert n_jobs parameter to a valid number of workers."""
        if n_jobs < 0:
            # Convert negative values to number of CPU cores minus absolute value
            cpu_count = os.cpu_count() or 1
            n_jobs = max(1, cpu_count + n_jobs + 1)
        return max(1, n_jobs)  # Ensure at least 1 worker
    
    def extract_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """Extract all features in parallel."""
        with ThreadPoolExecutor(max_workers=self.n_jobs) as executor:
            futures = []
            
            if 'filesystem' in self.feature_config:
                futures.append(
                    executor.submit(self.extract_filesystem_features, data)
                )
            if 'network' in self.feature_config:
                futures.append(
                    executor.submit(self.extract_network_features, data)
                )
            
            # Handle case when no features are configured
            if not futures:
                return pd.DataFrame(index=data.index)
            
            results = []
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logging.error(f"Feature extraction error: {str(e)}")
                    raise
            
            return pd.concat(results, axis=1) if results else pd.DataFrame(index=data.index)
    
    def extract_filesystem_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """Extract enhanced filesystem features."""
        features = pd.DataFrame()
        
        # File metadata features
        features['file_size'] = data['size'].fillna(0)
        features['file_size_log'] = np.log1p(features['file_size'])
        features['is_hidden'] = data['attributes'].apply(
            lambda x: 1 if 'hidden' in str(x).lower() else 0
        )
        
        # Advanced timestamp features
        timestamp_cols = ['created', 'modified', 'accessed']
        for col in timestamp_cols:
            if col in data.columns:
                timestamps = pd.to_datetime(data[col])
                features[f'{col}_hour'] = timestamps.dt.hour
                features[f'{col}_day'] = timestamps.dt.day
                features[f'{col}_month'] = timestamps.dt.month
                features[f'{col}_dayofweek'] = timestamps.dt.dayofweek
                features[f'{col}_weekend'] = timestamps.dt.dayofweek.isin([5, 6]).astype(int)
                features[f'{col}_business_hours'] = timestamps.dt.hour.between(9, 17).astype(int)
        
        # Timestamp differences
        if all(col in data.columns for col in timestamp_cols):
            for col1, col2 in zip(timestamp_cols[:-1], timestamp_cols[1:]):
                features[f'{col1}_{col2}_diff'] = (
                    pd.to_datetime(data[col2]) - pd.to_datetime(data[col1])
                ).dt.total_seconds()
        
        return features
    
    def extract_network_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """Extract enhanced network traffic features."""
        features = pd.DataFrame(index=data.index)
        
        # Basic network features
        features['packet_size'] = data['size'].fillna(0)
        features['protocol_type'] = pd.Categorical(data['protocol']).codes
        
        # Time-based features
        timestamps = pd.to_datetime(data['timestamp'])
        features['time_diff'] = timestamps.diff().dt.total_seconds().fillna(0)
        
        # Safe rate calculations
        epsilon = 1e-10
        features['packet_rate'] = np.where(
            features['time_diff'] > epsilon,
            1 / features['time_diff'],
            0
        )
        
        # Port analysis
        features['src_port_category'] = pd.Categorical(data['src_port']).codes
        features['dst_port_category'] = pd.Categorical(data['dst_port']).codes
        features['is_well_known_port_src'] = (data['src_port'] <= 1024).astype(int)
        features['is_well_known_port_dst'] = (data['dst_port'] <= 1024).astype(int)
        
        # Advanced port-based features
        for port_type in ['src_port', 'dst_port']:
            features[f'{port_type}_registered'] = (
                (data[port_type] > 1024) & (data[port_type] <= 49151)
            ).astype(int)
            features[f'{port_type}_dynamic'] = (data[port_type] > 49151).astype(int)
        
        # Protocol-specific features
        if 'protocol' in data.columns:
            protocol_dummies = pd.get_dummies(
                data['protocol'], prefix='protocol', dtype=int
            )
            features = pd.concat([features, protocol_dummies], axis=1)
        
        # Time window analysis
        if 'timestamp' in data.columns:
            timestamps = pd.to_datetime(data['timestamp'])
            window_sizes = [60, 300, 900]  # 1min, 5min, 15min windows
            
            for window in window_sizes:
                # Create a time-based grouping with unique index
                window_stats = data.groupby(
                    timestamps.dt.floor(f'{window}s')
                ).agg({
                    'size': ['count', 'mean', 'std']
                }).reset_index()
                
                # Flatten column names
                window_stats.columns = [
                    'timestamp',
                    f'packet_count_{window}s',
                    f'mean_size_{window}s',
                    f'std_size_{window}s'
                ]
                
                # Create a mapping dictionary from timestamp to window statistics
                stats_dict = {
                    col: window_stats.set_index('timestamp')[col].to_dict()
                    for col in window_stats.columns[1:]
                }
                
                # Map the statistics back to the original timestamps
                for col, value_dict in stats_dict.items():
                    features[col] = timestamps.dt.floor(f'{window}s').map(value_dict).fillna(0)
        
        # Ensure all features are numeric
        for column in features.columns:
            features[column] = pd.to_numeric(
                features[column], errors='coerce'
            ).fillna(0)
        
        return features

    def process_batch(self, data_batch: pd.DataFrame) -> pd.DataFrame:
        """Process features in batches for better memory management."""
        batch_size = 1000  # Configurable batch size
        results = []
        for i in range(0, len(data_batch), batch_size):
            batch = data_batch.iloc[i:i+batch_size]
            results.append(self.extract_features(batch))
        return pd.concat(results)

class ModelValidator:
    """Enhanced model validation system with advanced metrics and cross-validation."""
    
    def __init__(self, validation_types: Optional[List[str]] = None,
                 cv_folds: int = 5, random_state: int = 42):
        self.validation_types = validation_types or ['basic', 'forensic', 'advanced']
        self.cv_folds = cv_folds
        self.random_state = random_state
        self.metrics: Dict[str, Dict[str, float]] = {}
        
    def validate_model(self, model: BaseEstimator, X_test: np.ndarray,
                      y_test: np.ndarray, case_weights: Optional[np.ndarray] = None,
                      X_train: Optional[np.ndarray] = None,
                      y_train: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """Comprehensive model validation with multiple evaluation strategies."""
        validation_results = {}
        
        # Basic classification metrics
        y_pred = model.predict(X_test)
        
        # Handle predict_proba if available
        if hasattr(model, 'predict_proba'):
            y_pred_proba = model.predict_proba(X_test)
        else:
            y_pred_proba = None
        
        validation_results['basic_metrics'] = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, average='weighted'),
            'recall': recall_score(y_test, y_pred, average='weighted'),
            'f1': f1_score(y_test, y_pred, average='weighted')
        }
        
        # Calculate ROC AUC score appropriately based on number of classes
        if y_pred_proba is not None:
            n_classes = len(np.unique(y_test))
            if n_classes == 2:
                # Binary classification case
                validation_results['basic_metrics']['roc_auc'] = roc_auc_score(
                    y_test, y_pred_proba[:, 1]
                )
            else:
                # Multi-class case
                validation_results['basic_metrics']['roc_auc'] = roc_auc_score(
                    y_test, y_pred_proba, multi_class='ovr', average='weighted'
                )
        
        # Confusion matrix analysis
        conf_matrix = confusion_matrix(y_test, y_pred)
        validation_results['confusion_matrix'] = {
            'matrix': conf_matrix.tolist(),
            'normalized': (conf_matrix / conf_matrix.sum(axis=1)[:, np.newaxis]).tolist()
        }
        
        # Cross-validation if training data is provided
        if X_train is not None and y_train is not None:
            cv = StratifiedKFold(
                n_splits=self.cv_folds, shuffle=True,
                random_state=self.random_state
            )
            cv_scores = cross_val_score(
                model, X_train, y_train, cv=cv, scoring='f1_weighted'
            )
            validation_results['cross_validation'] = {
                'mean': cv_scores.mean(),
                'std': cv_scores.std(),
                'scores': cv_scores.tolist()
            }
        
        # Advanced validation for forensic analysis
        if 'forensic' in self.validation_types:
            validation_results['forensic_metrics'] = self._forensic_validation(
                y_test, y_pred, case_weights
            )
        
        # Stability analysis
        if 'advanced' in self.validation_types:
            validation_results['stability_metrics'] = self._stability_analysis(
                model, X_test, y_test
            )
        
        return validation_results
    
    def _forensic_validation(self, y_true: np.ndarray, y_pred: np.ndarray,
                           case_weights: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """Specialized validation metrics for forensic analysis."""
        metrics = {}
        
        # Convert labels to integers for bincount operation
        unique_labels = np.unique(y_true)
        label_mapping = {label: idx for idx, label in enumerate(unique_labels)}
        y_true_int = np.array([label_mapping[label] for label in y_true])
        
        # Class distribution analysis
        class_counts = np.bincount(y_true_int)
        class_distribution = class_counts / len(y_true)
        
        # Map the distribution back to original labels
        metrics['class_distribution'] = {
            str(unique_labels[i]): float(dist)
            for i, dist in enumerate(class_distribution)
        }
        
        # Per-class performance metrics
        class_metrics = {}
        for class_label in unique_labels:
            mask = y_true == class_label
            if np.any(mask):  # Only calculate if class is present
                class_metrics[f'class_{class_label}'] = {
                    'precision': precision_score(
                        y_true[mask], y_pred[mask], average='weighted',
                        zero_division=0
                    ),
                    'recall': recall_score(
                        y_true[mask], y_pred[mask], average='weighted',
                        zero_division=0
                    )
                }
        metrics['class_metrics'] = class_metrics
        
        # Weighted metrics if case weights are provided
        if case_weights is not None:
            metrics['weighted_accuracy'] = accuracy_score(
                y_true, y_pred, sample_weight=case_weights
            )
        
        return metrics
    
    def _stability_analysis(self, model: BaseEstimator, X: np.ndarray,
                          y: np.ndarray, n_iterations: int = 10) -> Dict[str, float]:
        """Analyze model prediction stability under small perturbations."""
        stability_metrics = {}
        
        # Convert DataFrame to numpy array, handling categorical columns properly
        X_numeric = X.select_dtypes(include=['int64', 'float64'])
        
        if len(X_numeric.columns) == 0:
            # If no numeric columns, return basic stability metrics
            stability_metrics['prediction_consistency'] = 1.0
            stability_metrics['noise_sensitivity'] = 0.0
            return stability_metrics
        
        # Initialize array for predictions
        predictions = []
        noise_scale = 0.01
        
        for _ in range(n_iterations):
            # Create a copy of the original DataFrame
            X_noisy = X.copy()
            
            # Add noise only to numeric columns
            noise = np.random.normal(0, noise_scale, X_numeric.shape)
            X_noisy[X_numeric.columns] = X_numeric + noise
            
            # Make predictions
            y_pred = model.predict(X_noisy)
            predictions.append(y_pred)
        
        # Calculate prediction consistency
        predictions = np.array(predictions)
        consistency = np.mean(
            [np.mean(predictions[i] == predictions[0])
            for i in range(1, n_iterations)]
        )
        
        stability_metrics['prediction_consistency'] = float(consistency)
        stability_metrics['noise_sensitivity'] = float(1 - consistency)
        
        return stability_metrics

    def _analyze_data_types(self, data: pd.DataFrame, results: Dict[str, Any]) -> None:
        match data.dtypes:
            case _ if len(data.select_dtypes(include=['int64', 'float64'])):
                results['statistics']['numeric_present'] = True
            case _ if len(data.select_dtypes(include=['object'])):
                results['statistics']['categorical_present'] = True
            case _:
                results['warnings'].append("Unknown data types detected")    

class PerformanceMonitor:
    """Enhanced performance monitoring system with drift detection."""
    
    def __init__(self, monitoring_config: Optional[Dict[str, Any]] = None):
        self.config = monitoring_config or {
            'performance_threshold': 0.1,
            'anomaly_detection_threshold': 0.95,
            'monitoring_window': 10,
            'drift_detection_window': 100
        }
        self.performance_history: List[Dict[str, Any]] = []
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self._setup_drift_detector()
    
    def _setup_drift_detector(self) -> None:
        """Initialize drift detection components."""
        self.drift_detector = {
            'reference_distribution': None,
            'p_value_threshold': 0.05,
            'window_size': self.config['drift_detection_window']
        }
    
    def analyze_performance(self, current_metrics: Dict[str, float],
                          feature_distribution: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """Comprehensive performance analysis including drift detection."""
        analysis_results = {
            'status': 'healthy',
            'warnings': [],
            'metrics': {}
        }
        
        # Performance trend analysis
        trend_analysis = self._analyze_performance_trend()
        analysis_results['metrics'].update(trend_analysis)
        
        # Anomaly detection
        if len(self.performance_history) >= self.config['monitoring_window']:
            anomalies = self._detect_anomalies(current_metrics)
            if anomalies:
                analysis_results['status'] = 'warning'
                analysis_results['warnings'].append(
                    'Anomalous performance detected'
                )
                analysis_results['metrics']['anomalies'] = anomalies
        
        # Drift detection
        if feature_distribution is not None:
            drift_detected = self._detect_distribution_drift(
                feature_distribution
            )
            if drift_detected:
                analysis_results['status'] = 'warning'
                analysis_results['warnings'].append('Data drift detected')
                analysis_results['metrics']['drift_detected'] = True
        
        return analysis_results
    
    def _analyze_performance_trend(self) -> Dict[str, float]:
        """Analyze historical performance trends."""
        if len(self.performance_history) < 2:
            return {'trend_status': 'insufficient_data'}
        
        recent_metrics = [
            entry['metrics']['f1']
            for entry in self.performance_history[-self.config['monitoring_window']:]
        ]
        
        trend_metrics = {
            'current_performance': recent_metrics[-1],
            'performance_change': recent_metrics[-1] - recent_metrics[0],
            'is_degrading': self._detect_degradation(recent_metrics)
        }
        
        return trend_metrics
    
    def _detect_anomalies(self, current_metrics: Dict[str, float]) -> List[str]:
        """Detect anomalous performance metrics."""
        anomalies = []
        reference_metrics = np.array([
            [m['metrics'][k] for k in current_metrics.keys()]
            for m in self.performance_history[-self.config['monitoring_window']:]
        ])
        
        current_vector = np.array([list(current_metrics.values())])
        
        try:
            self.anomaly_detector.fit(reference_metrics)
            prediction = self.anomaly_detector.predict(current_vector)
            
            if prediction[0] == -1:  # Anomaly detected
                anomalies = [
                    k for k, v in current_metrics.items()
                    if abs(v - np.mean(reference_metrics[:, list(current_metrics.keys()).index(k)]))
                    > 2 * np.std(reference_metrics[:, list(current_metrics.keys()).index(k)])
                ]
        except Exception as e:
            logging.warning(f"Anomaly detection failed: {str(e)}")
        
        return anomalies
    
    def _detect_distribution_drift(self, current_distribution: np.ndarray) -> bool:
        """Detect significant changes in feature distributions."""
        if self.drift_detector['reference_distribution'] is None:
            self.drift_detector['reference_distribution'] = current_distribution
            return False
        
        try:
            from scipy import stats
            
            # Perform Kolmogorov-Smirnov test
            statistic, p_value = stats.ks_2samp(
                self.drift_detector['reference_distribution'].ravel(),
                current_distribution.ravel()
            )
            
            return p_value < self.drift_detector['p_value_threshold']
            
        except Exception as e:
            logging.warning(f"Drift detection failed: {str(e)}")
            return False
    
    def log_performance(self, model_id: str, metrics: Dict[str, float],
                       timestamp: Optional[datetime] = None,
                       feature_distribution: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """Log and analyze model performance."""
        if timestamp is None:
            timestamp = datetime.now()
            
        performance_entry = {
            'model_id': model_id,
            'timestamp': timestamp,
            'metrics': metrics
        }
        
        self.performance_history.append(performance_entry)
        
        # Perform comprehensive analysis
        analysis_results = self.analyze_performance(
            metrics, feature_distribution
        )
        
        return analysis_results

class DataValidator:
    """Enhanced data validation system with comprehensive checks."""
    
    def __init__(self, validation_rules: Optional[Dict[str, Any]] = None):
        self.validation_rules = validation_rules or {
            'min_samples': 100,
            'max_missing_ratio': 0.1,
            'correlation_threshold': 0.95,
            'cardinality_threshold': 0.9,
            'outlier_threshold': 3
        }
    
    def validate_dataset(self, data: pd.DataFrame,
                        sensitive_columns: Optional[List[str]] = None) -> Dict[str, Any]:
        """Comprehensive dataset validation with security considerations."""
        validation_results = {
            'status': 'valid',
            'warnings': [],
            'errors': [],
            'statistics': {}
        }
        
        try:
            # Basic validation
            self._validate_basic_requirements(data, validation_results)
            
            # Data type analysis
            self._analyze_data_types(data, validation_results)
            
            # Missing value analysis
            self._analyze_missing_values(data, validation_results)
            
            # Statistical analysis
            self._perform_statistical_analysis(data, validation_results)
            
            # Security checks
            if sensitive_columns:
                self._perform_security_checks(
                    data, sensitive_columns, validation_results
                )
            
            # Set final status
            validation_results['status'] = (
                'valid' if not validation_results['errors'] else 'invalid'
            )
            
        except Exception as e:
            validation_results['status'] = 'error'
            validation_results['errors'].append(str(e))
        
        return validation_results
    
    def _validate_basic_requirements(self, data: pd.DataFrame,
                                   results: Dict[str, Any]) -> None:
        """Validate basic dataset requirements."""
        if len(data) < self.validation_rules['min_samples']:
            results['errors'].append(
                f"Insufficient samples: {len(data)} < "
                f"{self.validation_rules['min_samples']}"
            )
        
        if len(data.columns) == 0:
            results['errors'].append("Dataset contains no columns")
    
    def _analyze_data_types(self, data: pd.DataFrame,
                          results: Dict[str, Any]) -> None:
        """Analyze and validate data types."""
        results['statistics']['data_types'] = {
            'numeric_columns': data.select_dtypes(
                include=['int64', 'float64']
            ).columns.tolist(),
            'categorical_columns': data.select_dtypes(
                include=['object', 'category', 'datetime64']
            ).columns.tolist()
        }
        
        # Check for mixed data types within columns
        for column in data.columns:
            if data[column].dtype == 'object':
                type_counts = data[column].apply(type).value_counts()
                if len(type_counts) > 1:
                    results['warnings'].append(
                        f"Mixed data types in column {column}: {dict(type_counts)}"
                    )
    
    def _analyze_missing_values(self, data: pd.DataFrame,
                              results: Dict[str, Any]) -> None:
        """Analyze missing values and patterns."""
        missing_stats = {}
        missing_ratio = data.isnull().sum() / len(data)
        
        # Overall missing value statistics
        missing_stats['total_missing_ratio'] = missing_ratio.mean()
        missing_stats['columns_with_missing'] = missing_ratio[
            missing_ratio > 0
        ].to_dict()
        
        # Identify columns with high missing ratios
        high_missing = missing_ratio[
            missing_ratio > self.validation_rules['max_missing_ratio']
        ]
        if not high_missing.empty:
            results['warnings'].append(
                f"High missing ratio in columns: {high_missing.to_dict()}"
            )
        
        # Missing value patterns
        missing_patterns = data.isnull().sum(axis=1).value_counts().to_dict()
        missing_stats['missing_patterns'] = missing_patterns
        
        results['statistics']['missing_values'] = missing_stats
    
    def _perform_statistical_analysis(self, data: pd.DataFrame,
                                    results: Dict[str, Any]) -> None:
        """Perform comprehensive statistical analysis."""
        stats = {}
        
        # Numeric column analysis
        numeric_cols = data.select_dtypes(include=['int64', 'float64']).columns
        if len(numeric_cols) > 0:
            # Basic statistics
            stats['numeric'] = data[numeric_cols].describe().to_dict()
            
            # Correlation analysis
            if len(numeric_cols) > 1:
                correlation_matrix = data[numeric_cols].corr()
                high_correlation = np.where(
                    np.abs(correlation_matrix) > self.validation_rules['correlation_threshold']
                )
                high_correlation_pairs = [
                    (numeric_cols[x], numeric_cols[y])
                    for x, y in zip(*high_correlation)
                    if x != y and x < y
                ]
                if high_correlation_pairs:
                    results['warnings'].append(
                        f"High correlation between features: {high_correlation_pairs}"
                    )
            
            # Outlier detection
            stats['outliers'] = self._detect_outliers(data[numeric_cols])
        
        # Categorical column analysis
        categorical_cols = data.select_dtypes(
            include=['object', 'category']
        ).columns
        if len(categorical_cols) > 0:
            stats['categorical'] = {}
            for col in categorical_cols:
                unique_ratio = data[col].nunique() / len(data)
                if unique_ratio > self.validation_rules['cardinality_threshold']:
                    results['warnings'].append(
                        f"High cardinality in column {col}: "
                        f"{unique_ratio:.2%} unique values"
                    )
                
                stats['categorical'][col] = {
                    'unique_count': data[col].nunique(),
                    'unique_ratio': unique_ratio,
                    'top_values': data[col].value_counts().head().to_dict()
                }
        
        results['statistics']['statistical_analysis'] = stats
    
    def _detect_outliers(self, numeric_data: pd.DataFrame) -> Dict[str, Any]:
        """Detect outliers using multiple methods."""
        outlier_stats = {}
        
        for column in numeric_data.columns:
            column_stats = {}
            data = numeric_data[column].dropna()
            
            # Z-score method
            z_scores = np.abs((data - data.mean()) / data.std())
            z_score_outliers = z_scores > self.validation_rules['outlier_threshold']
            
            # IQR method
            Q1 = data.quantile(0.25)
            Q3 = data.quantile(0.75)
            IQR = Q3 - Q1
            iqr_outliers = (data < (Q1 - 1.5 * IQR)) | (data > (Q3 + 1.5 * IQR))
            
            column_stats['z_score_outliers'] = {
                'count': z_score_outliers.sum(),
                'percentage': z_score_outliers.mean() * 100
            }
            column_stats['iqr_outliers'] = {
                'count': iqr_outliers.sum(),
                'percentage': iqr_outliers.mean() * 100
            }
            
            outlier_stats[column] = column_stats
        
        return outlier_stats
    
    def _perform_security_checks(self, data: pd.DataFrame,
                               sensitive_columns: List[str],
                               results: Dict[str, Any]) -> None:
        """Perform security-related checks on sensitive data."""
        security_results = {}
        
        for column in sensitive_columns:
            if column not in data.columns:
                continue
            
            column_checks = {}
            
            # Check for potential PII patterns
            column_checks['potential_pii'] = self._check_pii_patterns(
                data[column]
            )
            
            # Check for unusual value patterns
            column_checks['unusual_patterns'] = self._check_unusual_patterns(
                data[column]
            )
            
            security_results[column] = column_checks
        
        if any(check['potential_pii'] for check in security_results.values()):
            results['warnings'].append(
                "Potential PII detected in sensitive columns"
            )
        
        results['statistics']['security_checks'] = security_results
    
    def _check_pii_patterns(self, series: pd.Series) -> bool:
        """Check for common PII patterns in data."""
        # Convert to string and check patterns
        str_series = series.astype(str)
        
        # Common PII patterns (simplified examples)
        patterns = {
            'email': r'[^@]+@[^@]+\.[^@]+',
            'phone': r'\d{3}[-.]?\d{3}[-.]?\d{4}',
            'ssn': r'\d{3}[-]?\d{2}[-]?\d{4}',
            'credit_card': r'\d{4}[-]?\d{4}[-]?\d{4}[-]?\d{4}'
        }
        
        for pattern_type, pattern in patterns.items():
            if str_series.str.contains(pattern, regex=True).any():
                return True
        
        return False
    
    def _check_unusual_patterns(self, series: pd.Series) -> Dict[str, Any]:
        """Check for unusual patterns in data."""
        patterns = {
            'repetitive_values': len(series.value_counts()) == 1,
            'sequential_values': self._check_sequential(series),
            'high_entropy': self._calculate_entropy(series)
        }
        return patterns
    
    def _check_sequential(self, series: pd.Series) -> bool:
        """Check if values appear to be sequential."""
        try:
            numeric_series = pd.to_numeric(series)
            diffs = numeric_series.diff().dropna()
            return len(diffs.unique()) == 1
        except:
            return False
    
    def _calculate_entropy(self, series: pd.Series) -> float:
        """Calculate Shannon entropy of the series."""
        value_counts = series.value_counts(normalize=True)
        return -sum(p * np.log2(p) for p in value_counts)

@dataclass(frozen=True)
class MLConfig:
    model_path: Path
    use_gpu: bool
    encryption_key: Optional[str]
    validation_rules: Dict[str, Any]
    monitoring_config: Dict[str, Any]
    feature_config: Dict[str, Any]

def example_usage():
    """
    Example demonstrating the enhanced ML utilities in a forensic analysis workflow.
    """
    import pandas as pd
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from datetime import datetime

    # Initialize components
    model_manager = ModelManager(
        model_path="./forensic_models",
        use_gpu=True,
        encryption_key=Fernet.generate_key()
    )
    feature_extractor = FeatureExtractor(
        n_jobs=-1,
        feature_config={
            'filesystem': True,
            'network': True
        }
    )
    validator = ModelValidator(['basic', 'forensic', 'advanced'])
    monitor = PerformanceMonitor({
        'performance_threshold': 0.1,
        'monitoring_window': 10,
        'drift_detection_window': 100
    })
    data_validator = DataValidator()

    try:
        # Generate sample data
        print("Generating sample forensic data...")
        n_samples = 1000
        n_anomalies = int(n_samples * 0.3)  # 30% anomalies for better balance
        
        # Create balanced labels first
        labels = np.concatenate([
            np.ones(n_anomalies),  # Anomalous cases
            np.zeros(n_samples - n_anomalies)  # Normal cases
        ])
        
        # Generate different patterns based on label
        sample_data = pd.DataFrame({
            'timestamp': pd.date_range(start='2024-01-01', periods=n_samples, freq='h'),
            'size': np.where(
                labels == 1,
                np.random.randint(800000, 1000000, n_samples),  # Larger sizes for anomalies
                np.random.randint(1000, 100000, n_samples)  # Normal sizes
            ),
            'attributes': pd.Categorical([
                'hidden' if label == 1 else 'normal' 
                for label in labels
            ]),
            'protocol': pd.Categorical([
                np.random.choice(['TCP', 'UDP', 'ICMP'], p=[0.4, 0.4, 0.2])
                for _ in range(n_samples)
            ]),
            'src_port': np.where(
                labels == 1,
                np.random.randint(50000, 65535, n_samples),  # High ports for anomalies
                np.random.randint(1, 49151, n_samples)  # Normal port range
            ),
            'dst_port': np.random.randint(1, 65535, n_samples),
            'created': pd.date_range(start='2024-01-01', periods=n_samples, freq='h'),
            'modified': pd.date_range(start='2024-01-02', periods=n_samples, freq='h'),
            'accessed': pd.date_range(start='2024-01-03', periods=n_samples, freq='h')
        })

        # Validate input data
        print("\nValidating input data...")
        validation_results = data_validator.validate_dataset(
            sample_data,
            sensitive_columns=['src_port', 'dst_port']
        )
        
        if validation_results['status'] != 'valid':
            print("Validation warnings:", validation_results['warnings'])
            print("Validation errors:", validation_results['errors'])
            if validation_results['status'] == 'invalid':
                raise ValueError("Data validation failed")

        # Extract features
        print("\nExtracting features...")
        features = feature_extractor.extract_features(sample_data)
        
        # Prepare data for modeling
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42, stratify=labels
        )

        # Train model with balanced class weights
        print("\nTraining model...")
        model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'  # Add class weights
        )
        model.fit(X_train, y_train)

        # Validate model with zero_division parameter
        print("\nValidating model...")
        validation_results = validator.validate_model(
            model=model,
            X_test=X_test,
            y_test=y_test,
            X_train=X_train,
            y_train=y_train
        )

        # Create model metadata
        model_metadata = ModelMetadata(
            model_id=str(uuid.uuid4()),
            creation_date=datetime.now(),
            last_updated=datetime.now(),
            training_data_hash=hashlib.blake2b(
                str(features).encode()
            ).hexdigest(),
            performance_metrics=validation_results['basic_metrics'],
            feature_columns=features.columns.tolist(),
            model_parameters=model.get_params(),
            version="1.0.0",
            author="system",
            description="Forensic analysis model with balanced classes",
            tags=['forensic', 'classification', 'balanced']
        )

        # Save model
        print("\nSaving model...")
        model_path = model_manager.save_model(model, model_metadata)
        print(f"Model saved to: {model_path}")

        # Monitor performance
        print("\nMonitoring performance...")
        monitoring_results = monitor.log_performance(
            model_id=model_metadata.model_id,
            metrics=validation_results['basic_metrics'],
            feature_distribution=X_test
        )
        
        print("\nPerformance monitoring results:")
        print(f"Status: {monitoring_results['status']}")
        if monitoring_results['warnings']:
            print("Warnings:", monitoring_results['warnings'])
        print("Metrics:", monitoring_results['metrics'])

        print("\nWorkflow completed successfully!")

    except Exception as e:
        print(f"Error in workflow: {str(e)}")
        raise

if __name__ == "__main__":
    example_usage()
