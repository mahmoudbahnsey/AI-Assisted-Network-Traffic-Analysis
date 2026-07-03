"""
Machine learning models for network attack detection
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import cross_val_score
import xgboost as xgb
import joblib
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class MLModels:
    """Container for multiple ML models"""
    
    def __init__(self, model_params: dict = None):
        """
        Initialize ML models
        
        Args:
            model_params: Dictionary of model hyperparameters
        """
        self.models = {}
        self.model_params = model_params or {}
        self.trained_models = {}
        
    def get_model(self, model_name: str):
        """
        Get a model instance by name
        
        Args:
            model_name: Name of the model
            
        Returns:
            Model instance
        """
        if model_name == 'random_forest':
            params = self.model_params.get('random_forest', {})
            return RandomForestClassifier(**params)
        
        elif model_name == 'svm':
            params = self.model_params.get('svm', {})
            return SVC(**params)
        
        elif model_name == 'xgboost':
            params = self.model_params.get('xgboost', {})
            return xgb.XGBClassifier(**params)
        
        elif model_name == 'decision_tree':
            params = self.model_params.get('decision_tree', {})
            return DecisionTreeClassifier(**params)
        
        elif model_name == 'logistic_regression':
            params = self.model_params.get('logistic_regression', {})
            return LogisticRegression(**params)
        
        else:
            raise ValueError(f"Unknown model: {model_name}")
    
    def train_model(self, model_name: str, X_train: np.ndarray, y_train: np.ndarray) -> object:
        """
        Train a single model
        
        Args:
            model_name: Name of the model to train
            X_train: Training features
            y_train: Training labels
            
        Returns:
            Trained model
        """
        logger.info(f"Training {model_name} model")
        
        model = self.get_model(model_name)
        model.fit(X_train, y_train)
        
        self.trained_models[model_name] = model
        logger.info(f"{model_name} model trained successfully")
        
        return model
    
    def train_all_models(self, X_train: np.ndarray, y_train: np.ndarray) -> dict:
        """
        Train all available models
        
        Args:
            X_train: Training features
            y_train: Training labels
            
        Returns:
            Dictionary of trained models
        """
        logger.info("Training all models")
        
        model_names = ['random_forest', 'svm', 'xgboost', 'decision_tree', 'logistic_regression']
        
        for model_name in model_names:
            try:
                self.train_model(model_name, X_train, y_train)
            except Exception as e:
                logger.error(f"Failed to train {model_name}: {e}")
        
        logger.info(f"Trained {len(self.trained_models)} models successfully")
        
        return self.trained_models
    
    def predict(self, model_name: str, X: np.ndarray) -> np.ndarray:
        """
        Make predictions using a trained model
        
        Args:
            model_name: Name of the model
            X: Features to predict
            
        Returns:
            Predictions
        """
        if model_name not in self.trained_models:
            raise ValueError(f"Model {model_name} not trained")
        
        model = self.trained_models[model_name]
        predictions = model.predict(X)
        
        return predictions
    
    def predict_proba(self, model_name: str, X: np.ndarray) -> np.ndarray:
        """
        Get prediction probabilities
        
        Args:
            model_name: Name of the model
            X: Features to predict
            
        Returns:
            Prediction probabilities
        """
        if model_name not in self.trained_models:
            raise ValueError(f"Model {model_name} not trained")
        
        model = self.trained_models[model_name]
        
        if hasattr(model, 'predict_proba'):
            return model.predict_proba(X)
        else:
            # For models without predict_proba (like SVM with probability=False)
            predictions = model.predict(X)
            # Convert to one-hot encoding
            n_classes = len(np.unique(predictions))
            proba = np.zeros((len(predictions), n_classes))
            for i, pred in enumerate(predictions):
                proba[i, pred] = 1.0
            return proba
    
    def save_model(self, model_name: str, output_path: str):
        """
        Save a trained model to disk
        
        Args:
            model_name: Name of the model to save
            output_path: Path to save the model
        """
        if model_name not in self.trained_models:
            raise ValueError(f"Model {model_name} not trained")
        
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        joblib.dump(self.trained_models[model_name], output_path)
        logger.info(f"Saved {model_name} model to {output_path}")
    
    def load_model(self, model_name: str, model_path: str):
        """
        Load a trained model from disk
        
        Args:
            model_name: Name to assign to the loaded model
            model_path: Path to the model file
        """
        model_path = Path(model_path)
        
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        self.trained_models[model_name] = joblib.load(model_path)
        logger.info(f"Loaded {model_name} model from {model_path}")
    
    def get_feature_importance(self, model_name: str, feature_names: list) -> pd.DataFrame:
        """
        Get feature importance from a trained model
        
        Args:
            model_name: Name of the model
            feature_names: List of feature names
            
        Returns:
            DataFrame with feature importance
        """
        if model_name not in self.trained_models:
            raise ValueError(f"Model {model_name} not trained")
        
        model = self.trained_models[model_name]
        
        if hasattr(model, 'feature_importances_'):
            importance = model.feature_importances_
        elif hasattr(model, 'coef_'):
            importance = np.abs(model.coef_[0])
        else:
            logger.warning(f"Model {model_name} does not support feature importance")
            return pd.DataFrame()
        
        df = pd.DataFrame({
            'feature': feature_names,
            'importance': importance
        }).sort_values('importance', ascending=False)
        
        return df
    
    def cross_validate_model(self, 
                           model_name: str, 
                           X: np.ndarray, 
                           y: np.ndarray, 
                           cv: int = 5) -> dict:
        """
        Perform cross-validation on a model
        
        Args:
            model_name: Name of the model
            X: Features
            y: Labels
            cv: Number of cross-validation folds
            
        Returns:
            Dictionary with cross-validation scores
        """
        logger.info(f"Cross-validating {model_name} with {cv} folds")
        
        model = self.get_model(model_name)
        scores = cross_val_score(model, X, y, cv=cv, scoring='accuracy')
        
        result = {
            'model': model_name,
            'mean_accuracy': scores.mean(),
            'std_accuracy': scores.std(),
            'scores': scores.tolist()
        }
        
        logger.info(f"CV Results - Mean: {result['mean_accuracy']:.4f}, Std: {result['std_accuracy']:.4f}")
        
        return result
