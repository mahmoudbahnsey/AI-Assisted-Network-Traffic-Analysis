"""
Model evaluation and selection system
"""

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve
)
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import logging
import json

logger = logging.getLogger(__name__)


class ModelEvaluator:
    """Evaluate and compare ML models for attack detection"""
    
    def __init__(self):
        self.evaluation_results = {}
        self.best_model = None
        
    def evaluate_model(self, 
                      model_name: str,
                      model: object,
                      X_test: np.ndarray,
                      y_test: np.ndarray,
                      average: str = 'weighted') -> dict:
        """
        Evaluate a single model
        
        Args:
            model_name: Name of the model
            model: Trained model object
            X_test: Test features
            y_test: Test labels
            average: Averaging method for multi-class metrics
            
        Returns:
            Dictionary with evaluation metrics
        """
        logger.info(f"Evaluating {model_name}")
        
        # Make predictions
        y_pred = model.predict(X_test)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average=average, zero_division=0)
        recall = recall_score(y_test, y_pred, average=average, zero_division=0)
        f1 = f1_score(y_test, y_pred, average=average, zero_division=0)
        
        # Calculate confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        
        # Try to get ROC AUC if available
        try:
            if hasattr(model, 'predict_proba'):
                y_proba = model.predict_proba(X_test)
                if len(np.unique(y_test)) == 2:
                    roc_auc = roc_auc_score(y_test, y_proba[:, 1])
                else:
                    roc_auc = roc_auc_score(y_test, y_proba, multi_class='ovr')
            else:
                roc_auc = None
        except:
            roc_auc = None
        
        result = {
            'model_name': model_name,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'roc_auc': roc_auc,
            'confusion_matrix': cm.tolist(),
            'classification_report': classification_report(y_test, y_pred, output_dict=True)
        }
        
        self.evaluation_results[model_name] = result
        
        logger.info(f"{model_name} - Accuracy: {accuracy:.4f}, F1: {f1:.4f}")
        
        return result
    
    def evaluate_all_models(self,
                          trained_models: dict,
                          X_test: np.ndarray,
                          y_test: np.ndarray) -> dict:
        """
        Evaluate all trained models
        
        Args:
            trained_models: Dictionary of trained models
            X_test: Test features
            y_test: Test labels
            
        Returns:
            Dictionary with all evaluation results
        """
        logger.info("Evaluating all models")
        
        for model_name, model in trained_models.items():
            try:
                self.evaluate_model(model_name, model, X_test, y_test)
            except Exception as e:
                logger.error(f"Failed to evaluate {model_name}: {e}")
        
        return self.evaluation_results
    
    def select_best_model(self, metric: str = 'f1_score') -> str:
        """
        Select the best performing model based on a metric
        
        Args:
            metric: Metric to use for selection
            
        Returns:
            Name of the best model
        """
        if not self.evaluation_results:
            raise ValueError("No evaluation results available")
        
        best_model_name = None
        best_score = -1
        
        for model_name, result in self.evaluation_results.items():
            score = result.get(metric, 0)
            if score > best_score:
                best_score = score
                best_model_name = model_name
        
        self.best_model = best_model_name
        logger.info(f"Best model: {best_model_name} ({metric}: {best_score:.4f})")
        
        return best_model_name
    
    def get_comparison_table(self) -> pd.DataFrame:
        """
        Get a comparison table of all models
        
        Returns:
            DataFrame with model comparison
        """
        if not self.evaluation_results:
            return pd.DataFrame()
        
        comparison_data = []
        for model_name, result in self.evaluation_results.items():
            comparison_data.append({
                'Model': model_name,
                'Accuracy': result['accuracy'],
                'Precision': result['precision'],
                'Recall': result['recall'],
                'F1 Score': result['f1_score'],
                'ROC AUC': result.get('roc_auc', 'N/A')
            })
        
        df = pd.DataFrame(comparison_data).sort_values('F1 Score', ascending=False)
        
        return df
    
    def plot_confusion_matrix(self, model_name: str, save_path: str = None):
        """
        Plot confusion matrix for a model
        
        Args:
            model_name: Name of the model
            save_path: Path to save the plot
        """
        if model_name not in self.evaluation_results:
            raise ValueError(f"No evaluation results for {model_name}")
        
        cm = np.array(self.evaluation_results[model_name]['confusion_matrix'])
        
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title(f'Confusion Matrix - {model_name}')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        
        if save_path:
            save_path = Path(save_path)
            save_path.parent.mkdir(parents=True, exist_ok=True)
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"Saved confusion matrix plot to {save_path}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_model_comparison(self, save_path: str = None):
        """
        Plot comparison of all models
        
        Args:
            save_path: Path to save the plot
        """
        if not self.evaluation_results:
            raise ValueError("No evaluation results available")
        
        df = self.get_comparison_table()
        
        # Melt the DataFrame for plotting
        metrics = ['Accuracy', 'Precision', 'Recall', 'F1 Score']
        df_melted = df.melt(id_vars=['Model'], value_vars=metrics, var_name='Metric', value_name='Score')
        
        plt.figure(figsize=(12, 6))
        sns.barplot(data=df_melted, x='Model', y='Score', hue='Metric')
        plt.title('Model Comparison')
        plt.ylabel('Score')
        plt.xlabel('Model')
        plt.legend(title='Metric')
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        if save_path:
            save_path = Path(save_path)
            save_path.parent.mkdir(parents=True, exist_ok=True)
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"Saved model comparison plot to {save_path}")
        else:
            plt.show()
        
        plt.close()
    
    def save_evaluation_results(self, output_path: str):
        """
        Save evaluation results to JSON
        
        Args:
            output_path: Path to save the results
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert numpy arrays to lists for JSON serialization
        results_serializable = {}
        for model_name, result in self.evaluation_results.items():
            results_serializable[model_name] = {
                'model_name': result['model_name'],
                'accuracy': float(result['accuracy']),
                'precision': float(result['precision']),
                'recall': float(result['recall']),
                'f1_score': float(result['f1_score']),
                'roc_auc': float(result['roc_auc']) if result['roc_auc'] is not None else None,
                'confusion_matrix': result['confusion_matrix'],
                'classification_report': result['classification_report']
            }
        
        with open(output_path, 'w') as f:
            json.dump(results_serializable, f, indent=2)
        
        logger.info(f"Saved evaluation results to {output_path}")
    
    def load_evaluation_results(self, input_path: str):
        """
        Load evaluation results from JSON
        
        Args:
            input_path: Path to load the results from
        """
        input_path = Path(input_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Evaluation results file not found: {input_path}")
        
        with open(input_path, 'r') as f:
            self.evaluation_results = json.load(f)
        
        logger.info(f"Loaded evaluation results from {input_path}")
    
    def print_summary(self):
        """Print a summary of evaluation results"""
        if not self.evaluation_results:
            print("No evaluation results available")
            return
        
        print("\n" + "="*60)
        print("MODEL EVALUATION SUMMARY")
        print("="*60)
        
        df = self.get_comparison_table()
        print(df.to_string(index=False))
        
        if self.best_model:
            print(f"\nBest Model: {self.best_model}")
        
        print("="*60 + "\n")
