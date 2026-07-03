"""
Data preprocessing pipeline for network traffic data
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class DataPreprocessor:
    """Preprocess network traffic data for ML models"""
    
    def __init__(self, test_size: float = 0.2, random_state: int = 42):
        """
        Initialize data preprocessor
        
        Args:
            test_size: Proportion of data to use for testing
            random_state: Random seed for reproducibility
        """
        self.test_size = test_size
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_columns = []
        
    def load_data(self, data_path: str) -> pd.DataFrame:
        """
        Load data from CSV file
        
        Args:
            data_path: Path to CSV file
            
        Returns:
            DataFrame with loaded data
        """
        data_path = Path(data_path)
        
        if not data_path.exists():
            raise FileNotFoundError(f"Data file not found: {data_path}")
        
        df = pd.read_csv(data_path)
        logger.info(f"Loaded data from {data_path}: {len(df)} rows, {len(df.columns)} columns")
        
        return df
    
    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean data by handling missing values and duplicates
        
        Args:
            df: Input DataFrame
            
        Returns:
            Cleaned DataFrame
        """
        logger.info("Cleaning data")
        
        # Remove duplicates
        initial_count = len(df)
        df = df.drop_duplicates()
        duplicates_removed = initial_count - len(df)
        logger.info(f"Removed {duplicates_removed} duplicate rows")
        
        # Handle missing values
        missing_count = df.isnull().sum().sum()
        if missing_count > 0:
            logger.info(f"Found {missing_count} missing values")
            
            # Fill numerical columns with median
            numerical_cols = df.select_dtypes(include=[np.number]).columns
            for col in numerical_cols:
                df[col] = df[col].fillna(df[col].median())
            
            # Fill categorical columns with mode
            categorical_cols = df.select_dtypes(include=['object']).columns
            for col in categorical_cols:
                df[col] = df[col].fillna(df[col].mode()[0] if not df[col].mode().empty else 'unknown')
        
        return df
    
    def encode_categorical_features(self, df: pd.DataFrame, target_column: str = None) -> pd.DataFrame:
        """
        Encode categorical features
        
        Args:
            df: Input DataFrame
            target_column: Name of target column (if any)
            
        Returns:
            DataFrame with encoded features
        """
        logger.info("Encoding categorical features")
        
        df_encoded = df.copy()
        
        # Get categorical columns (excluding target if specified)
        categorical_cols = df_encoded.select_dtypes(include=['object']).columns
        if target_column:
            categorical_cols = categorical_cols.drop(target_column, errors='ignore')
        
        # Encode each categorical column
        for col in categorical_cols:
            if col not in self.label_encoders:
                self.label_encoders[col] = LabelEncoder()
                df_encoded[col] = self.label_encoders[col].fit_transform(df_encoded[col].astype(str))
            else:
                df_encoded[col] = self.label_encoders[col].transform(df_encoded[col].astype(str))
        
        # Encode target column if specified
        if target_column and target_column in df_encoded.columns:
            if target_column not in self.label_encoders:
                self.label_encoders[target_column] = LabelEncoder()
                df_encoded[target_column] = self.label_encoders[target_column].fit_transform(
                    df_encoded[target_column].astype(str)
                )
            else:
                df_encoded[target_column] = self.label_encoders[target_column].transform(
                    df_encoded[target_column].astype(str)
                )
        
        return df_encoded
    
    def select_features(self, df: pd.DataFrame, target_column: str = None) -> pd.DataFrame:
        """
        Select relevant features for ML models
        
        Args:
            df: Input DataFrame
            target_column: Name of target column
            
        Returns:
            DataFrame with selected features
        """
        logger.info("Selecting features")
        
        # Remove non-numeric columns that can't be used directly
        df_selected = df.copy()
        
        # Columns to exclude
        exclude_cols = ['id.orig_h', 'id.resp_h', 'query', 'host', 'uri', 'user_agent']
        exclude_cols = [col for col in exclude_cols if col in df_selected.columns]
        df_selected = df_selected.drop(columns=exclude_cols, errors='ignore')
        
        # Remove columns with all NaN or constant values
        constant_cols = []
        for col in df_selected.columns:
            if df_selected[col].nunique() <= 1:
                constant_cols.append(col)
        
        if constant_cols:
            logger.info(f"Removing {len(constant_cols)} constant columns")
            df_selected = df_selected.drop(columns=constant_cols, errors='ignore')
        
        # Store feature columns
        if target_column:
            self.feature_columns = [col for col in df_selected.columns if col != target_column]
        else:
            self.feature_columns = list(df_selected.columns)
        
        return df_selected
    
    def scale_features(self, df: pd.DataFrame, fit: bool = True) -> pd.DataFrame:
        """
        Scale numerical features
        
        Args:
            df: Input DataFrame
            fit: Whether to fit the scaler
            
        Returns:
            DataFrame with scaled features
        """
        logger.info("Scaling features")
        
        df_scaled = df.copy()
        
        # Get numerical columns
        numerical_cols = df_scaled.select_dtypes(include=[np.number]).columns
        
        if fit:
            df_scaled[numerical_cols] = self.scaler.fit_transform(df_scaled[numerical_cols])
        else:
            df_scaled[numerical_cols] = self.scaler.transform(df_scaled[numerical_cols])
        
        return df_scaled
    
    def handle_imbalanced_data(self, X: np.ndarray, y: np.ndarray) -> tuple:
        """
        Handle imbalanced data using SMOTE
        
        Args:
            X: Feature matrix
            y: Target vector
            
        Returns:
            Resampled X and y
        """
        logger.info("Handling imbalanced data with SMOTE")
        
        unique_classes = np.unique(y)
        if len(unique_classes) < 2:
            logger.warning("Only one class present, skipping SMOTE")
            return X, y
        
        smote = SMOTE(random_state=self.random_state)
        X_resampled, y_resampled = smote.fit_resample(X, y)
        
        logger.info(f"Resampled data: {len(X)} -> {len(X_resampled)} samples")
        
        return X_resampled, y_resampled
    
    def split_data(self, df: pd.DataFrame, target_column: str) -> tuple:
        """
        Split data into train and test Sets
        
        Args:
            df: Input DataFrame
            target_column: Name of target column
            
        Returns:
            X_train, X_test, y_train, y_test
        """
        logger.info(f"Splitting data with test_size={self.test_size}")
        
        X = df.drop(columns=[target_column])
        y = df[target_column]
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=self.test_size, 
            random_state=self.random_state,
            stratify=y
        )
        
        logger.info(f"Train set: {len(X_train)} samples")
        logger.info(f"Test set: {len(X_test)} samples")
        
        return X_train, X_test, y_train, y_test
    
    def preprocess_pipeline(self, 
                           data_path: str,
                           target_column: str,
                           apply_smote: bool = True,
                           scale: bool = True) -> dict:
        """
        Complete preprocessing pipeline
        
        Args:
            data_path: Path to data file
            target_column: Name of target column
            apply_smote: Whether to apply SMOTE for imbalanced data
            scale: Whether to scale features
            
        Returns:
            Dictionary with processed data
        """
        logger.info("Starting preprocessing pipeline")
        
        # Load data
        df = self.load_data(data_path)
        
        # Clean data
        df = self.clean_data(df)
        
        # Encode categorical features
        df = self.encode_categorical_features(df, target_column)
        
        # Select features
        df = self.select_features(df, target_column)
        
        # Split data
        X_train, X_test, y_train, y_test = self.split_data(df, target_column)
        
        # Apply SMOTE if requested
        if apply_smote:
            X_train, y_train = self.handle_imbalanced_data(X_train, y_train)
        
        # Scale features if requested
        if scale:
            X_train = self.scale_features(X_train, fit=True)
            X_test = self.scale_features(X_test, fit=False)
        
        result = {
            'X_train': X_train,
            'X_test': X_test,
            'y_train': y_train,
            'y_test': y_test,
            'feature_columns': self.feature_columns,
            'label_encoders': self.label_encoders
        }
        
        logger.info("Preprocessing pipeline completed")
        
        return result
    
    def save_processed_data(self, data: dict, output_dir: str):
        """
        Save processed data to files
        
        Args:
            data: Dictionary with processed data
            output_dir: Output directory
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save as numpy arrays
        np.save(output_path / 'X_train.npy', data['X_train'])
        np.save(output_path / 'X_test.npy', data['X_test'])
        np.save(output_path / 'y_train.npy', data['y_train'])
        np.save(output_path / 'y_test.npy', data['y_test'])
        
        # Save feature columns
        import json
        with open(output_path / 'feature_columns.json', 'w') as f:
            json.dump(data['feature_columns'], f)
        
        logger.info(f"Saved processed data to {output_path}")
