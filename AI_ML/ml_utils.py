import os
import pickle
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, Embedding, Dropout
from transformers import BertTokenizer, TFBertForSequenceClassification
from transformers import Trainer, TrainingArguments
import torch
from ray import tune
from ray.tune.schedulers import ASHAScheduler

# Constants
MODEL_DIR = "models"
DATA_DIR = "data"
LOG_DIR = "logs"

# Ensure directories exist
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

class MLUtils:
    def __init__(self, error_manager):  # Accept error_manager as a parameter
        self.models = {}  # Dictionary to store trained models
        self.scaler = StandardScaler()  # Scaler for preprocessing
        self.tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')  # BERT tokenizer
        self.error_manager = error_manager  # Initialize error manager

    def load_model(self, model_name):
        """
        Load a pre-trained model from disk.
        """
        try:
            model_path = os.path.join(MODEL_DIR, f"{model_name}.pkl")
            if os.path.exists(model_path):
                with open(model_path, "rb") as f:
                    self.models[model_name] = pickle.load(f)
                print(f"Model {model_name} loaded successfully.")
            else:
                print(f"Model {model_name} not found.")
        except Exception as e:
            # Log the error
            self.error_manager.log_error("Model Loading Error", "Critical", f"Error loading model {model_name}: {str(e)}")

    def save_model(self, model, model_name):
        """
        Save a trained model to disk.
        """
        try:
            model_path = os.path.join(MODEL_DIR, f"{model_name}.pkl")
            with open(model_path, "wb") as f:
                pickle.dump(model, f)
            print(f"Model {model_name} saved successfully.")
        except Exception as e:
            # Log the error
            self.error_manager.log_error("Model Saving Error", "Critical", f"Error saving model {model_name}: {str(e)}")

    def preprocess_data(self, data, feature_columns, target_column=None):
        """
        Preprocess data for machine learning training.
        """
        try:
            X = data[feature_columns]
            if target_column:
                y = data[target_column]
                return self.scaler.fit_transform(X), y
            return self.scaler.fit_transform(X)
        except Exception as e:
            # Log the error
            self.error_manager.log_error("Data Preprocessing Error", "Warning", f"Error preprocessing data: {str(e)}")
            return None, None

    def train_model(self, model_type, X_train, y_train, **kwargs):
        """
        Train a machine learning model.
        """
        try:
            if model_type == "IsolationForest":
                model = IsolationForest(**kwargs)
            elif model_type == "RandomForest":
                model = RandomForestClassifier(**kwargs)
            elif model_type == "SVM":
                model = SVC(**kwargs)
            elif model_type == "LSTM":
                model = self._build_lstm_model(X_train.shape[1])
            elif model_type == "BERT":
                model = self._build_bert_model()
            else:
                raise ValueError(f"Unsupported model type: {model_type}")

            if model_type in ["IsolationForest", "RandomForest", "SVM"]:
                model.fit(X_train, y_train)
            elif model_type == "LSTM":
                X_train = np.reshape(X_train, (X_train.shape[0], X_train.shape[1], 1))
                model.fit(X_train, y_train, epochs=10, batch_size=32, verbose=1)
            elif model_type == "BERT":
                train_dataset = self._prepare_bert_dataset(X_train, y_train)
                training_args = TrainingArguments(output_dir=LOG_DIR, num_train_epochs=3, per_device_train_batch_size=16)
                trainer = Trainer(model=model, args=training_args, train_dataset=train_dataset)
                trainer.train()

            self.models[model_type] = model
            self.save_model(model, model_name=model_type)
            return model
        except Exception as e:
            # Log the error
            self.error_manager.log_error("Model Training Error", "Critical", f"Error training {model_type} model: {str(e)}")
            return None

    def evaluate_model(self, model_type, X_test, y_test):
        """
        Evaluate a model's performance.
        """
        try:
            model = self.models.get(model_type)
            if not model:
                raise ValueError(f"Model {model_type} not found.")

            if model_type == "LSTM":
                X_test = np.reshape(X_test, (X_test.shape[0], X_test.shape[1], 1))
                y_pred = (model.predict(X_test) > 0.5).astype("int32")
            elif model_type == "BERT":
                test_dataset = self._prepare_bert_dataset(X_test, y_test)
                trainer = Trainer(model=model)
                predictions = trainer.predict(test_dataset)
                y_pred = np.argmax(predictions.predictions, axis=-1)
            else:
                y_pred = model.predict(X_test)

            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, average="weighted")
            recall = recall_score(y_test, y_pred, average="weighted")
            f1 = f1_score(y_test, y_pred, average="weighted")

            print(f"Model {model_type} Evaluation:")
            print(f"Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1-Score: {f1:.4f}")
        except Exception as e:
            # Log the error
            self.error_manager.log_error("Model Evaluation Error", "Critical", f"Error evaluating {model_type} model: {str(e)}")

    def _build_lstm_model(self, input_shape):
        """
        Build an LSTM model for sequence-based anomaly detection.
        """
        try:
            model = Sequential()
            model.add(LSTM(64, input_shape=(input_shape, 1), return_sequences=True))
            model.add(Dropout(0.2))
            model.add(LSTM(32, return_sequences=False))
            model.add(Dense(1, activation="sigmoid"))
            model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
            return model
        except Exception as e:
            # Log the error
            self.error_manager.log_error("LSTM Model Building Error", "Critical", f"Error building LSTM model: {str(e)}")
            return None

    def _build_bert_model(self):
        """
        Build a BERT model for NLP-based text analysis.
        """
        try:
            model = TFBertForSequenceClassification.from_pretrained('bert-base-uncased', num_labels=2)
            return model
        except Exception as e:
            # Log the error
            self.error_manager.log_error("BERT Model Building Error", "Critical", f"Error building BERT model: {str(e)}")
            return None

    def _prepare_bert_dataset(self, texts, labels):
        """
        Prepare a dataset for BERT training.
        """
        try:
            encodings = self.tokenizer(texts.tolist(), truncation=True, padding=True, max_length=512)
            dataset = torch.utils.data.TensorDataset(
                torch.tensor(encodings['input_ids']),
                torch.tensor(encodings['attention_mask']),
                torch.tensor(labels)
            )
            return dataset
        except Exception as e:
            # Log the error
            self.error_manager.log_error("BERT Dataset Preparation Error", "Warning", f"Error preparing BERT dataset: {str(e)}")
            return None

    def hyperparameter_tuning(self, model_type, config, X_train, y_train):
        """
        Perform hyperparameter tuning using Ray Tune.
        """
        try:
            def trainable(config):
                model = self.train_model(model_type, X_train, y_train, **config)
                y_pred = model.predict(X_train)
                tune.report(accuracy=accuracy_score(y_train, y_pred))

            scheduler = ASHAScheduler(metric="accuracy", mode="max")
            analysis = tune.run(
                trainable,
                config=config,
                scheduler=scheduler,
                num_samples=10,
                resources_per_trial={"cpu": 2, "gpu": 1}
            )
            best_config = analysis.get_best_config(metric="accuracy", mode="max")
            print(f"Best hyperparameters: {best_config}")
            return best_config
        except Exception as e:
            # Log the error
            self.error_manager.log_error("Hyperparameter Tuning Error", "Critical", f"Error during hyperparameter tuning: {str(e)}")
            return None
