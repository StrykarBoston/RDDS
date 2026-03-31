import pandas as pd
import numpy as np
import joblib
import tensorflow as tf
import os
import warnings
from core.config import DATA_DIR

warnings.filterwarnings('ignore')

class NetworkThreatPredictor:
    def __init__(self, model_path=os.path.join(DATA_DIR, 'traffic_model.h5'), scaler_path=os.path.join(DATA_DIR, 'traffic_scaler.pkl')):
        try:
            if not os.path.exists(model_path) or not os.path.exists(scaler_path):
                self.model_loaded = False
                return

            self.traffic_model = tf.keras.models.load_model(model_path)
            self.traffic_scaler = joblib.load(scaler_path)
            self.model_loaded = True
        except Exception as e:
            print(f"Error loading AI model: {e}")
            self.model_loaded = False

    def analyze_network_traffic(self, feature_dict):
        """
        Takes a dictionary of network features and predicts if it's an Evil Twin.
        Returns safety score, risk level, and probabilities.
        """
        if not self.model_loaded:
            return {'error': "AI Model not loaded."}
        try:
            feature_df = pd.DataFrame([feature_dict])
            for feature in self.traffic_scaler.feature_names_in_:
                if feature not in feature_df.columns:
                    feature_df[feature] = 0
            
            feature_df = feature_df[self.traffic_scaler.feature_names_in_].fillna(0)
            for col in feature_df.columns:
                feature_df[col] = pd.to_numeric(feature_df[col], errors='coerce')
                
            feature_df = feature_df.replace([np.inf, -np.inf], 0)
            feature_df = feature_df.fillna(0)
            
            # Scale features
            feature_scaled = self.traffic_scaler.transform(feature_df)
            
            # Reshape for CNN/LSTM if required by the model
            if len(self.traffic_model.input_shape) == 3:
                feature_scaled = feature_scaled.reshape(feature_scaled.shape[0], feature_scaled.shape[1], 1)
                
            prediction_prob = self.traffic_model.predict(feature_scaled, verbose=0)[0][0]
            
            if prediction_prob > 0.7:
                is_anomalous = True
                safety_score = (1 - prediction_prob) * 100
            elif prediction_prob < 0.3:
                is_anomalous = False
                safety_score = (1 - prediction_prob) * 100
            else:
                is_anomalous = prediction_prob > 0.5
                safety_score = 50
                
            # Formatting results
            if is_anomalous:
                if safety_score < 30:
                    recommendation = "CRITICAL THREAT DETECTED! Disconnect immediately! Possible network attack."
                else:
                    recommendation = "Suspicious network behavior detected."
            else:
                if safety_score >= 80:
                    recommendation = "Network traffic appears legitimate."
                else:
                    recommendation = "Network shows minor background anomalies."
                    
            return {
                'safety_score': round(safety_score, 2),
                'safety_level': "SAFE" if safety_score >= 70 else "CAUTION" if safety_score >= 50 else "UNSAFE",
                'recommendation': recommendation,
                'is_anomalous': bool(is_anomalous),
                'probability_attack': float(prediction_prob),
                'probability_legitimate': float(1 - prediction_prob)
            }
        except Exception as e:
            return {'error': f"AI Analysis failed: {e}"}
