# detection_engine_multiclass.py

import numpy as np
import joblib
import os

class MultiClassDetectionEngine:
    def __init__(self, model_path="models"):
        self.classifier = joblib.load(os.path.join(model_path, "rf_multiclass_model.pkl"))
        self.scaler = joblib.load(os.path.join(model_path, "scaler_multiclass.pkl"))
        self.label_encoder = joblib.load(os.path.join(model_path, "label_encoder_multiclass.pkl"))
        self.signature_rules = self.load_signature_rules()

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: (
                    features['tcp_flags'] == 2 and
                    features['packet_rate'] > 100
                )
            },
            'port_scan': {
                'condition': lambda features: (
                    features['packet_size'] < 100 and
                    features['packet_rate'] > 50
                )
            }
        }

    def detect_threats(self, features: dict) -> list:
        threats = []

        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                })

        # Multi-class classifier prediction
        vector = np.array([[features.get(k, 0.0) for k in [
            'packet_size', 'flow_duration', 'packet_rate', 'byte_rate', 'window_size'
        ]]])
        vector_scaled = self.scaler.transform(vector)
        pred_class = self.classifier.predict(vector_scaled)[0]
        label = self.label_encoder.inverse_transform([pred_class])[0]

        confidence = (
            max(self.classifier.predict_proba(vector_scaled)[0])
            if hasattr(self.classifier, 'predict_proba') else 1.0
        )

        threats.append({
            'type': 'classifier',
            'label': label,
            'confidence': confidence
        })

        return threats
