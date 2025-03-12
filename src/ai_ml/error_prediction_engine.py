from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union
import asyncio
import json
import logging
from pathlib import Path

import aiohttp
import numpy as np
import pandas as pd
import ray
import torch
import torch.nn as nn
from prometheus_client import Counter, Gauge, start_http_server
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, Dataset

@dataclass
class SystemMetrics:
    cpu_usage: float
    memory_usage: float
    disk_io: float
    network_latency: float
    error_count: int
    process_count: int
    thread_count: int
    network_packets: int
    disk_queue_length: float
    swap_usage: float
    system_calls: int
    context_switches: int
    timestamp: datetime
    gpu_usage: Optional[float] = None
    container_metrics: Optional[Dict[str, float]] = None

    def to_array(self) -> np.ndarray:
        """Convert metrics to numpy array for model input."""
        return np.array([
            self.cpu_usage, self.memory_usage, self.disk_io,
            self.network_latency, self.error_count, self.process_count,
            self.thread_count, self.network_packets, self.disk_queue_length,
            self.swap_usage, self.system_calls, self.context_switches
        ])

class DeepLSTM(nn.Module):
    def __init__(self, input_size: int, hidden_size: int, num_layers: int, output_size: int, dropout_rate: float = 0.2):
        super().__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout_rate if num_layers > 1 else 0
        )
        self.dropout = nn.Dropout(dropout_rate)
        self.fc = nn.Linear(hidden_size, output_size)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        device = x.device
        batch_size = x.size(0)
        h0 = torch.zeros(self.num_layers, batch_size, self.hidden_size).to(device)
        c0 = torch.zeros(self.num_layers, batch_size, self.hidden_size).to(device)
        
        out, _ = self.lstm(x, (h0, c0))
        out = self.dropout(out[:, -1, :])
        return self.fc(out)

class MetricsDataset(Dataset):
    def __init__(self, features: np.ndarray, labels: np.ndarray, sequence_length: int):
        self.features = torch.FloatTensor(features)
        self.labels = torch.FloatTensor(labels)
        self.sequence_length = sequence_length

    def __len__(self) -> int:
        return len(self.features) - self.sequence_length

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor]:
        return (
            self.features[idx:idx + self.sequence_length],
            self.labels[idx + self.sequence_length]
        )

@ray.remote
class DistributedAnalyzer:
    def __init__(self, model_path: str = 'models'):
        self.model_path = Path(model_path)
        self.model = None
        self.scaler = None

    def analyze_batch(self, batch_data: np.ndarray) -> np.ndarray:
        if self.model is None:
            self._load_models()
        scaled_data = self.scaler.transform(batch_data)
        return self.model.predict_proba(scaled_data)

    def _load_models(self) -> None:
        self.model = torch.load(self.model_path / 'analyzer_model.pt')
        self.scaler = torch.load(self.model_path / 'analyzer_scaler.pt')

@dataclass
class PredictionResult:
    prediction: float
    confidence: float
    uncertainty: Dict[str, float]
    model_weights: Dict[str, float]

class ErrorPredictionEngine:
    def __init__(
        self,
        history_window: int = 24,
        prediction_threshold: float = 0.8,
        anomaly_sensitivity: float = 0.1,
        use_gpu: bool = True,
        model_path: str = 'models',
        num_analyzers: int = 4
    ):
        self.config = self._init_config(
            history_window, prediction_threshold,
            anomaly_sensitivity, use_gpu, model_path
        )
        self.metrics_history: List[SystemMetrics] = []
        self.device = self._setup_device(use_gpu)
        
        # Initialize components
        self.models = self._init_models()
        self.monitoring = self._init_monitoring()
        self.logger = self._setup_logging()
        
        # Initialize distributed computing
        ray.init(ignore_reinit_error=True)
        self.analyzers = [
            DistributedAnalyzer.remote(model_path)
            for _ in range(num_analyzers)
        ]

    @staticmethod
    def _init_config(
        history_window: int,
        prediction_threshold: float,
        anomaly_sensitivity: float,
        use_gpu: bool,
        model_path: str
    ) -> dict:
        return {
            'history_window': history_window,
            'prediction_threshold': prediction_threshold,
            'anomaly_sensitivity': anomaly_sensitivity,
            'use_gpu': use_gpu,
            'model_path': Path(model_path),
            'version': '2.1.0'
        }

    def _setup_device(self, use_gpu: bool) -> torch.device:
        return torch.device('cuda' if use_gpu and torch.cuda.is_available() else 'cpu')

    def _init_models(self) -> dict:
        return {
            'lstm': self._init_lstm_model(),
            'ensemble': RandomForestClassifier(n_estimators=100, max_depth=None, random_state=42),
            'anomaly': IsolationForest(contamination=self.config['anomaly_sensitivity'], random_state=42),
            'scaler': StandardScaler()
        }

    def _init_lstm_model(self) -> DeepLSTM:
        return DeepLSTM(
            input_size=12,
            hidden_size=64,
            num_layers=3,
            output_size=3
        ).to(self.device)

    def _init_monitoring(self) -> dict:
        start_http_server(8000)
        return {
            'metrics_gauge': Gauge('system_metrics', 'Current system metrics', ['metric_name']),
            'prediction_counter': Counter('predictions_total', 'Total number of predictions made'),
            'anomaly_counter': Counter('anomalies_detected', 'Total number of anomalies detected')
        }

    async def predict_errors(self) -> PredictionResult:
        """Make predictions with confidence scores and uncertainty estimates."""
        if len(self.metrics_history) < self.config['history_window']:
            raise ValueError("Insufficient historical data for prediction")

        data = self._prepare_prediction_data()
        predictions = await self._distributed_prediction(data)
        
        return PredictionResult(
            prediction=self._combine_predictions(predictions),
            confidence=self._calculate_confidence(predictions),
            uncertainty=self._estimate_uncertainty(predictions),
            model_weights=self._get_model_weights()
        )

    async def monitor_and_predict(self) -> None:
        """Main monitoring and prediction loop with error handling and logging."""
        while True:
            try:
                metrics = await self._collect_metrics()
                self.metrics_history.append(metrics)
                
                prediction_result = await self.predict_errors()
                self._update_monitoring(prediction_result)
                
                if self._requires_optimization(prediction_result):
                    await self._optimize_resources()
                
                await self._generate_report(prediction_result)
                
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {str(e)}", exc_info=True)
            
            await asyncio.sleep(60)

    def save_models(self) -> None:
        """Save all models and configurations."""
        model_path = self.config['model_path']
        model_path.mkdir(exist_ok=True)
        
        torch.save(self.models['lstm'].state_dict(), model_path / 'lstm_model.pt')
        torch.save(self.models['ensemble'], model_path / 'ensemble_model.pt')
        torch.save(self.models['scaler'], model_path / 'scaler.pt')
        
        with open(model_path / 'config.json', 'w') as f:
            json.dump(self.config, f, indent=2)

    @classmethod
    def load_models(cls, model_path: str) -> 'ErrorPredictionEngine':
        """Load a previously saved model instance."""
        model_path = Path(model_path)
        with open(model_path / 'config.json', 'r') as f:
            config = json.load(f)
        
        instance = cls(**config)
        instance.models['lstm'].load_state_dict(
            torch.load(model_path / 'lstm_model.pt')
        )
        instance.models['ensemble'] = torch.load(model_path / 'ensemble_model.pt')
        instance.models['scaler'] = torch.load(model_path / 'scaler.pt')
        
        return instance
